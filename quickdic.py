import pwnagotchi.plugins as plugins
import logging
import subprocess
import os
import threading
import time
import glob
import string
import signal # Added import

import pwnagotchi # Added for pwnagotchi.config access

# Pwnagotchi plugin imports

'''
Aircrack-ng needed, to install:
> apt-get install aircrack-ng
Upload wordlist files in .txt format to folder in config file (Default: /opt/wordlists/)
Cracked handshakes stored in handshake folder as [essid].pcap.cracked
'''
# Define constants for crack results
CRACK_SUCCESS = "CRACK_SUCCESS"
CRACK_NOT_FOUND = "CRACK_NOT_FOUND"
CRACK_ERROR = "CRACK_ERROR"
CRACK_PREVENTED = "CRACK_PREVENTED" # Added to signify a crack was prevented (e.g. CPU hot, already cracking)

# Define status codes for logging and internal state
STATUS_BOOTING = 0
STATUS_IDLE = 1
STATUS_SCANNING = 2
STATUS_CRACKING = 3
STATUS_CPU_HOT = 4
STATUS_ERROR = 5
STATUS_NO_WORDLISTS = 6
STATUS_HANDSHAKE_VERIFY_FAIL = 7
STATUS_AIRCRACK_FAIL = 8
STATUS_CRACKED = 9
STATUS_NOT_FOUND_SCAN = 10
STATUS_HS_TIMEOUT = 11 # Added for consistency, was string "HS Timeout"
STATUS_TIMEOUT = 12 # Added for consistency, was string "Timeout"

class QuickDic(plugins.Plugin):
    __author__ = 'Kamish'
    __version__ = '1.2.3'
    __license__ = 'GPL3'
    __description__ = 'Run a dictionary scan against captured handshakes (new and existing), with CPU temp check, timeout, progress logging, and avoidance of re-attempts. Scans periodically.'
    __name__ = 'QuickDic'

    def __init__(self):
        super().__init__()
        logging.debug("[quickdic] QuickDic plugin initializing")
        self.cracking_in_progress = False
        self.aircrack_proc_handle = None # Added to store aircrack Popen object
        # Options related to plugin behavior, configurable via config.toml
        self.options = {
            'wordlist_folder': '/opt/wordlists/',  # Default path to wordlists
            'max_cpu_temp': 80.0,                # Default maximum CPU temperature
            'aircrack_timeout': 300              # Default timeout for aircrack-ng in seconds
        }
        self._scan_thread = None
        self._stop_event = threading.Event()
        self.main_config_for_scan = None
        self.current_status = STATUS_BOOTING # Initial status set directly
        self.enabled_on_system = True # Initialize the flag, will be checked in on_loaded
        logging.debug(f"[quickdic] __init__: current_status = {self.current_status}")

    def on_loaded(self):
        # Check if running on Linux, if not, disable the plugin
        if os.name != 'posix':
            logging.warning("[quickdic] This plugin is designed to run on Linux (e.g., Raspberry Pi). Disabling plugin on non-POSIX system.")
            self.enabled_on_system = False 
        else:
            self.enabled_on_system = True

        if not self.enabled_on_system:
            logging.info("[quickdic] Plugin not enabled on this system. Skipping further initialization and disabling periodic scan.")
            self.current_status = STATUS_ERROR # Or a new status like STATUS_DISABLED_PLATFORM
            # Prevent the scan thread from starting if not on Linux
            if hasattr(self, '_scan_thread') and self._scan_thread is not None:
                logging.info("[quickdic] Scan thread will not be started as plugin is disabled on this platform.")
            return

        logging.info(f"Quick dictionary check plugin loaded (v{self.__version__})")

        # Define defaults for actual configurable options
        plugin_specific_defaults = {
            'wordlist_folder': '/opt/wordlists/',
            'max_cpu_temp': 80.0,
            'aircrack_timeout': 300
        }
        
        config_loaded_options = self.options.copy() if isinstance(self.options, dict) else {}

        if hasattr(super(), 'on_loaded'):
             super().on_loaded() # This call might modify self.options

        processed_options = {}
        for key, default_value in plugin_specific_defaults.items():

            value_to_process = None
            if isinstance(self.options, dict) and key in self.options:
                value_to_process = self.options[key]
            elif key in config_loaded_options: # Fallback if super().on_loaded() cleared/changed self.options unexpectedly
                value_to_process = config_loaded_options[key]
            
            if value_to_process is not None:
                try:
                    processed_options[key] = type(default_value)(value_to_process)
                except (ValueError, TypeError):
                    logging.warning(f"[quickdic] Invalid type for option '{key}' in config (value: {value_to_process}). Using default: {default_value}")
                    processed_options[key] = default_value
            else:
                processed_options[key] = default_value
        
        self.options = processed_options # Now self.options contains only our defined, type-checked settings.

        self.current_status = STATUS_BOOTING 
        logging.info(f"[quickdic] on_loaded: Initial status set to {self.current_status} after option processing. Configured options: {self.options}")

        wordlist_folder = self.options['wordlist_folder']
        logging.info(f"[quickdic] Checking for wordlists in: {wordlist_folder}")
        if not os.path.isdir(wordlist_folder):
            logging.warning(f"[quickdic] Wordlist folder '{wordlist_folder}' does not exist. Please create it.")
            self.current_status = STATUS_NO_WORDLISTS
        else:
            wordlist_files = glob.glob(os.path.join(wordlist_folder, "*.txt"))
            if not wordlist_files:
                logging.warning(f"[quickdic] No .txt wordlists found in '{wordlist_folder}'.")
                self.current_status = STATUS_NO_WORDLISTS
            else:
                logging.info(f"[quickdic] Found {len(wordlist_files)} wordlist(s).")

        try:
            check_cmd = "/usr/bin/dpkg -l aircrack-ng | grep aircrack-ng | awk '{print $2, $3}'"
            check_proc = subprocess.run(check_cmd, shell=True, stdout=subprocess.PIPE, universal_newlines=True, timeout=10)
            if "aircrack-ng" not in check_proc.stdout:
                logging.error("[quickdic] aircrack-ng not found. This plugin requires it.")
                self.current_status = STATUS_AIRCRACK_FAIL
        except Exception as e:
            logging.error(f"[quickdic] Error checking for aircrack-ng: {e}")
            self.current_status = STATUS_ERROR

        if hasattr(pwnagotchi, 'config') and isinstance(pwnagotchi.config, dict) and 'main' in pwnagotchi.config:
            self.main_config_for_scan = pwnagotchi.config['main']
            if not ('bettercap' in self.main_config_for_scan and 'handshakes_path' in self.main_config_for_scan['bettercap']):
                logging.error("[quickdic] 'bettercap' or 'handshakes_path' not found in main Pwnagotchi config.")
                self.main_config_for_scan = None
        else:
            logging.error("[quickdic] Pwnagotchi global config not found or invalid.")
            self.main_config_for_scan = None

        if self.main_config_for_scan and not (self.current_status == STATUS_NO_WORDLISTS or self.current_status == STATUS_AIRCRACK_FAIL):
            logging.info("[quickdic] Starting periodic handshake scan thread.")
            self._scan_thread = threading.Thread(target=self._periodic_scan_loop, daemon=True)
            self._scan_thread.start()
        else:
            logging.warning("[quickdic] Periodic handshake scan thread not started due to missing config or critical errors.")

        # Determine final status for on_loaded
        if self.current_status == STATUS_BOOTING: # If still booting, means no critical errors were detected
            self.current_status = STATUS_IDLE
        # If self.current_status was set to an error state, it remains as is.
        
        logging.info(f"[quickdic] on_loaded: Completed. Final status: {self.current_status}")

    def _periodic_scan_loop(self):
        if not self.enabled_on_system:
            logging.info("[quickdic] Plugin disabled on this system. Periodic scan loop will not run.")
            return

        logging.info("[quickdic] Periodic scan loop initiated.")
        
        try:
            self._stop_event.wait(5) # Initial delay before first scan
            while not self._stop_event.is_set():
                # Wait if a cracking process is already running
                while self.cracking_in_progress and not self._stop_event.is_set():
                    logging.debug("[quickdic] Cracking in progress, waiting for it to complete before next scan pass.")
                    self._stop_event.wait(10) # Wait for 10 seconds before checking again
                
                if self._stop_event.is_set(): # Check again after the inner loop
                    break

                if self.main_config_for_scan and \
                   self.current_status != STATUS_NO_WORDLISTS and \
                   self.current_status != STATUS_AIRCRACK_FAIL:

                    logging.debug("[quickdic] Starting a scan pass for existing handshakes.")
                    self.current_status = STATUS_SCANNING
                    
                    self._scan_and_crack_existing(self.main_config_for_scan)
                    
                    logging.debug("[quickdic] Scan pass completed.")
                    if self.current_status not in [STATUS_ERROR, STATUS_CPU_HOT]:
                         self.current_status = STATUS_IDLE
                else:
                    if not self.main_config_for_scan:
                        logging.warning("[quickdic] Main config not available for periodic scan. Loop paused.")
                    self._stop_event.wait(60)
                    if not self.main_config_for_scan and hasattr(pwnagotchi, 'config') and 'main' in pwnagotchi.config:
                        self.main_config_for_scan = pwnagotchi.config['main'].get('bettercap', {}).get('handshakes_path') and pwnagotchi.config['main']

                logging.debug("[quickdic] Waiting 30 seconds before next scan pass.")
                self._stop_event.wait(30)
        except Exception as e:
            logging.error(f"[quickdic] Exception in periodic scan loop: {e}", exc_info=True)
            self.current_status = STATUS_ERROR
        finally:
            logging.info("[quickdic] Periodic scan loop terminated.")

    def on_unload(self, ui): # ui parameter is still passed by pwnagotchi, even if not used by this plugin
        thread_name = threading.current_thread().name
        logging.info(f"[quickdic] [{thread_name}] on_unload called.")
        
        if hasattr(self, '_stop_event'):
            self._stop_event.set()
        if hasattr(self, '_scan_thread') and self._scan_thread and self._scan_thread.is_alive():
            logging.info(f"[quickdic] [{thread_name}] Joining scan thread...")
            self._scan_thread.join(timeout=5)
            if self._scan_thread.is_alive():
                logging.warning(f"[quickdic] [{thread_name}] Scan thread did not terminate in time.")

        # Attempt to kill aircrack-ng if it's running during unload
        if self.cracking_in_progress and self.aircrack_proc_handle:
            logging.info(f"[quickdic] Cracking was in progress during unload. Attempting to kill aircrack-ng process (PID: {self.aircrack_proc_handle.pid}).")
            killed = self._kill_aircrack_process(self.aircrack_proc_handle, "unload_cleanup")
            if killed:
                self.cracking_in_progress = False
                self.aircrack_proc_handle = None
                logging.info("[quickdic] Aircrack-ng process terminated during unload.")
            else:
                logging.warning("[quickdic] Failed to terminate aircrack-ng process during unload. It may still be running.")
        
        logging.info(f"[quickdic] [{thread_name}] Plugin unloaded.")

    def _kill_aircrack_process(self, proc_to_kill, ap_name_for_log="<unknown AP>"):
        """Robustly kills the given process (expected to be aircrack-ng)."""
        if proc_to_kill is None:
            logging.debug(f"[quickdic] _kill_aircrack_process called with None process for {ap_name_for_log}.")
            return True # No process to kill

        if proc_to_kill.poll() is not None:
            logging.debug(f"[quickdic] Process for {ap_name_for_log} (PID: {proc_to_kill.pid}) already terminated before kill attempt.")
            return True

        logging.info(f"[quickdic] Attempting to kill aircrack-ng process for {ap_name_for_log} (PID: {proc_to_kill.pid}).")
        
        try:
            if os.name != 'nt':
                pgid = os.getpgid(proc_to_kill.pid)
                logging.info(f"[quickdic] Sending SIGINT to PGID {pgid} (PID: {proc_to_kill.pid}).")
                os.killpg(pgid, signal.SIGINT)
                try:
                    proc_to_kill.wait(timeout=1) # Graceful shutdown time
                    logging.info(f"[quickdic] Process {proc_to_kill.pid} (PGID {pgid}) terminated gracefully after SIGINT.")
                    return True
                except subprocess.TimeoutExpired:
                    logging.warning(f"[quickdic] Process {proc_to_kill.pid} (PGID {pgid}) did not terminate after SIGINT. Sending SIGKILL.")
                    os.killpg(pgid, signal.SIGKILL)
                    proc_to_kill.wait(timeout=1) # Wait for SIGKILL to take effect
                    if proc_to_kill.poll() is None:
                        logging.error(f"[quickdic] FAILED TO KILL process {proc_to_kill.pid} (PGID {pgid}) even after SIGKILL.")
                        return False
                    else:
                        logging.info(f"[quickdic] Process {proc_to_kill.pid} (PGID {pgid}) terminated after SIGKILL.")
                        return True
                except ProcessLookupError: # PGID/PID gone after SIGINT
                    logging.info(f"[quickdic] Process/PGID for {proc_to_kill.pid} disappeared after SIGINT (presumed terminated).")
                    return True
            else: # Windows
                logging.info(f"[quickdic] Terminating process {proc_to_kill.pid} (Windows).")
                proc_to_kill.terminate()
                try:
                    proc_to_kill.wait(timeout=1)
                    logging.info(f"[quickdic] Process {proc_to_kill.pid} terminated gracefully (Windows).")
                    return True
                except subprocess.TimeoutExpired:
                    logging.warning(f"[quickdic] Process {proc_to_kill.pid} did not terminate gracefully. Killing (Windows).")
                    proc_to_kill.kill()
                    proc_to_kill.wait(timeout=1)
                    if proc_to_kill.poll() is None:
                        logging.error(f"[quickdic] FAILED TO KILL process {proc_to_kill.pid} (Windows) even after kill().")
                        return False
                    else:
                        logging.info(f"[quickdic] Process {proc_to_kill.pid} terminated after kill() (Windows).")
                        return True
                        
        except ProcessLookupError: # Main PID gone before we could get PGID or kill
            logging.warning(f"[quickdic] Process/PGID {proc_to_kill.pid} not found during kill attempt (likely already dead).")
            return True # Already dead
        except Exception as e:
            logging.error(f"[quickdic] Error during kill process for {proc_to_kill.pid} ({ap_name_for_log}): {e}", exc_info=True)
            # If an error occurs, check poll status one last time.
            if proc_to_kill.poll() is None:
                logging.warning(f"[quickdic] Process {proc_to_kill.pid} still appears to be running after kill exception.")
                return False
            else:
                logging.info(f"[quickdic] Process {proc_to_kill.pid} confirmed terminated after kill exception.")
                return True
        # Should have returned by now. If not, poll one last time.
        if proc_to_kill.poll() is None:
            logging.error(f"[quickdic] Process {proc_to_kill.pid} ({ap_name_for_log}) still running after kill logic completion. This shouldn't happen.")
            return False
        return True

    def _scan_and_crack_existing(self, main_config):
        logging.info("[quickdic] Scanning for existing unattempted handshakes...")
        if not main_config or 'bettercap' not in main_config or 'handshakes_path' not in main_config['bettercap']:
            logging.error("[quickdic] Handshake path not found in configuration. Cannot scan existing handshakes.")
            self.current_status = STATUS_ERROR
            logging.warning(f"[quickdic] _scan_and_crack_existing: Set status to ERROR ({self.current_status})")
            return

        handshakes_path = main_config['bettercap']['handshakes_path']
        if not os.path.isdir(handshakes_path):
            logging.error(f"[quickdic] Configured handshakes_path '{handshakes_path}' is not a valid directory.")
            self.current_status = STATUS_ERROR
            logging.warning(f"[quickdic] _scan_and_crack_existing: Set status to ERROR ({self.current_status})")
            return
            
        logging.info(f"[quickdic] Scanning directory: {handshakes_path}")
        self.current_status = STATUS_SCANNING
        logging.debug(f"[quickdic] _scan_and_crack_existing start: current_status = {self.current_status}")
        

        files_to_process = glob.glob(os.path.join(handshakes_path, "*.pcap"))
        logging.info(f"[quickdic] Found {len(files_to_process)} .pcap files in {handshakes_path}.")
        processed_a_file = False

        for pcap_file in files_to_process:
            if self._stop_event.is_set():
                logging.info("[quickdic] Stop event set, breaking from scan loop in _scan_and_crack_existing.")
                break
            
            base_filename = os.path.basename(pcap_file)
            cracked_filepath = pcap_file + ".cracked"
            failed_marker_filepath = pcap_file + ".quickdic_failed"

            if os.path.exists(cracked_filepath):
                logging.debug(f"[quickdic] Skipping already cracked file: {base_filename}")
                continue
            if os.path.exists(failed_marker_filepath):
                logging.debug(f"[quickdic] Skipping previously failed/attempted file: {base_filename}")
                continue
            
            processed_a_file = True
            logging.info(f"[quickdic] Found existing unattempted handshake: {base_filename}")
            essid_from_filename = base_filename.split('_')[0] if '_' in base_filename else base_filename.replace(".pcap", "")
            
            crack_result = self._try_crack_handshake(pcap_file, essid_from_filename)

            if crack_result == CRACK_NOT_FOUND or crack_result == CRACK_ERROR:
                try:
                    with open(failed_marker_filepath, 'w') as f: pass
                    logging.info(f"[quickdic] Marked {base_filename} as failed/attempted by quickdic.")
                except Exception as e:
                    logging.error(f"[quickdic] Could not create failed marker {failed_marker_filepath}: {e}")
            
            if self._stop_event.is_set(): break
            logging.debug(f"[quickdic] Pausing briefly after processing {base_filename}...")
            self._stop_event.wait(5)

        if not processed_a_file:
            logging.info("[quickdic] No new handshakes to process in this pass.")
        
        logging.debug(f"[quickdic] _scan_and_crack_existing finished a pass.")

    def _try_crack_handshake(self, pcap_filepath, access_point_name):
        if not self.enabled_on_system:
            logging.warning(f"[quickdic] Plugin disabled on this system. Skipping crack attempt for {access_point_name}.")
            return CRACK_PREVENTED # Or a more specific status

        logging.info(f"[quickdic] Attempting to crack: {access_point_name} from file: {pcap_filepath}")
        
        if self.cracking_in_progress: # Check before setting True for this attempt
            logging.info(f"[quickdic] Another cracking process is already running (PID: {self.aircrack_proc_handle.pid if self.aircrack_proc_handle else 'unknown'}). Skipping {access_point_name} for now.")
            return CRACK_PREVENTED

        self.cracking_in_progress = True # Set true for this attempt
        self.current_status = STATUS_CRACKING
        # self.aircrack_proc_handle is already None or set by a previous run that failed to clean up.
        # It will be explicitly set to None in finally if this attempt cleans up properly.
        # If a previous run left it non-None and cracking_in_progress False, this is a state anomaly.
        # However, the check above should prevent re-entry if cracking_in_progress is True.
        # For safety, ensure it's None before a new Popen if we proceed.
        if self.aircrack_proc_handle is not None:
            logging.warning(f"[quickdic] self.aircrack_proc_handle was not None at the start of _try_crack_handshake for {access_point_name} despite cracking_in_progress being False. This indicates a prior cleanup issue. Forcing to None.")
            self.aircrack_proc_handle = None


        max_temp = float(self.options.get('max_cpu_temp', 80.0))
        timeout_seconds = int(self.options.get('aircrack_timeout', 300))
        wordlist_folder = self.options.get('wordlist_folder', '/opt/wordlists/')
        
        current_temp = self._get_cpu_temperature()
        if current_temp is not None and current_temp > max_temp:
            logging.warning(f"[quickdic] CPU temp ({current_temp:.1f}°C) > limit ({max_temp}°C). Skipping {access_point_name}.")
            self.current_status = STATUS_CPU_HOT
            self.cracking_in_progress = False # Reset: no process started
            return CRACK_PREVENTED

        handshake_check_cmd = f'''/usr/bin/aircrack-ng "{pcap_filepath}" | grep "1 handshake" | awk '{{print $2}}' '''
        bssid_result = ""
        try:
            result_proc = subprocess.run(handshake_check_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, timeout=30)
            bssid_result = result_proc.stdout.translate({ord(c): None for c in string.whitespace})
            if result_proc.stderr:
                logging.debug(f"[quickdic] Handshake check stderr for {pcap_filepath}: {result_proc.stderr.strip()}")
        except subprocess.TimeoutExpired:
            logging.warning(f"[quickdic] Handshake check timed out for {pcap_filepath}.")
            self.current_status = STATUS_HS_TIMEOUT
            self.cracking_in_progress = False # Reset: no process started
            return CRACK_ERROR
        except Exception as e:
            logging.error(f"[quickdic] Error during handshake check for {pcap_filepath}: {e}", exc_info=True)
            self.current_status = STATUS_HANDSHAKE_VERIFY_FAIL
            self.cracking_in_progress = False # Reset: no process started
            return CRACK_ERROR

        if not bssid_result:
            logging.info(f"[quickdic] No handshake confirmed in {pcap_filepath}.")
            self.current_status = STATUS_HANDSHAKE_VERIFY_FAIL
            self.cracking_in_progress = False # Reset: no process started
            return CRACK_ERROR
        
        wordlist_files = glob.glob(os.path.join(wordlist_folder, "*.txt"))
        if not wordlist_files:
            logging.warning(f"[quickdic] No .txt wordlists found in {wordlist_folder}.")
            self.current_status = STATUS_NO_WORDLISTS
            self.cracking_in_progress = False # Reset: no process started
            return CRACK_ERROR

        wordlist_argument_string = ','.join(f'"{w}"' for w in wordlist_files)
        cracked_file_output_path = f"{pcap_filepath}.cracked"
        
        # Construct the base aircrack-ng command
        base_aircrack_cmd = f'''aircrack-ng -w {wordlist_argument_string} -l "{cracked_file_output_path}" -q -b {bssid_result} "{pcap_filepath}"'''
        
        # Prepend timeout command for non-Windows systems
        if os.name != 'nt':
            aircrack_cmd_str = f'''timeout {timeout_seconds}s {base_aircrack_cmd}'''
        else:
            aircrack_cmd_str = base_aircrack_cmd
        
        # Local proc for this attempt, self.aircrack_proc_handle will also be set
        local_proc_handle = None 
        aircrack_return_status = CRACK_ERROR # Default to error
        
        try:
            logging.debug(f"[quickdic] Executing aircrack-ng: {aircrack_cmd_str}")
            # preexec_fn=os.setsid is for POSIX to allow killing the whole process group.
            local_proc_handle = subprocess.Popen(aircrack_cmd_str, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, 
                                    universal_newlines=True, preexec_fn=os.setsid if os.name != 'nt' else None)
            self.aircrack_proc_handle = local_proc_handle # Assign to instance member
            
            stdout_data, stderr_data = "", ""
            try:
                stdout_data, stderr_data = local_proc_handle.communicate(timeout=timeout_seconds)
                
                if stderr_data: # Log stderr
                    for line in stderr_data.strip().splitlines():
                        if ("No networks found, exiting." in line or
                            "Please specify a dictionary" in line or
                            ("Opening" in line and "failed: No such file or directory" in line) or
                            "Unsupported KDF type" in line or
                            "No valid WPA handshakes found" in line):
                            logging.info(f"[quickdic] aircrack-ng info/stderr: {line.strip()}")
                        elif "Read error: Broken pipe" in line: 
                            logging.debug(f"[quickdic] aircrack-ng stderr (broken pipe): {line.strip()}")
                        else:
                            logging.warning(f"[quickdic] aircrack-ng stderr: {line.strip()}")
                
                if stdout_data: # Log stdout
                    for line in stdout_data.strip().splitlines():
                        logging.debug(f"[quickdic] aircrack-ng stdout: {line.strip()}")

                if os.path.exists(cracked_file_output_path):
                    logging.info(f"[quickdic] KEY FOUND for {access_point_name}. Verified by presence of {cracked_file_output_path}")
                    self.current_status = STATUS_CRACKED
                    aircrack_return_status = CRACK_SUCCESS
                else:
                    if local_proc_handle.returncode != 0:
                         logging.warning(f"[quickdic] aircrack-ng for {access_point_name} exited with code {local_proc_handle.returncode} and no .cracked file found.")
                         aircrack_return_status = CRACK_ERROR 
                    else:
                         logging.info(f"[quickdic] Aircrack-ng completed (exit 0) for {access_point_name}, but no .cracked file. Password not found.")
                         aircrack_return_status = CRACK_NOT_FOUND
            
            except subprocess.TimeoutExpired:
                logging.info(f"[quickdic] Aircrack-ng timed out for {access_point_name} after {timeout_seconds}s.")
                self.current_status = STATUS_TIMEOUT
                aircrack_return_status = CRACK_ERROR
                
                if local_proc_handle and local_proc_handle.poll() is None:
                    logging.info(f"[quickdic] Attempting to kill timed-out aircrack-ng process for {access_point_name} (PID: {local_proc_handle.pid}).")
                    # Result of kill is handled by finally block's check on cracking_in_progress
                    self._kill_aircrack_process(local_proc_handle, access_point_name)
                # stdout/stderr from communicate() before timeout are not available here,
                # but if proc.stdout/stderr were captured by Popen, they might have partial data.
                # However, communicate() was called, so pipes are likely closed or in an unusable state.

        except FileNotFoundError:
            logging.error(f"[quickdic] aircrack-ng command not found. Ensure it is installed and in PATH.")
            self.current_status = STATUS_AIRCRACK_FAIL
            aircrack_return_status = CRACK_ERROR
            # self.cracking_in_progress will be set to False in finally
            # self.aircrack_proc_handle is None
        except Exception as e:
            logging.error(f"[quickdic] General error running aircrack-ng for {access_point_name}: {e}", exc_info=True)
            self.current_status = STATUS_ERROR
            aircrack_return_status = CRACK_ERROR
            # self.cracking_in_progress state depends on whether proc was initialized. Finally handles it.
        finally:
            # Ensure self.aircrack_proc_handle is the one we worked with, or None if Popen failed
            current_proc_to_finalize = self.aircrack_proc_handle 
            
            if current_proc_to_finalize:
                if current_proc_to_finalize.stdout and not current_proc_to_finalize.stdout.closed:
                    current_proc_to_finalize.stdout.close()
                if current_proc_to_finalize.stderr and not current_proc_to_finalize.stderr.closed:
                    current_proc_to_finalize.stderr.close()

                process_confirmed_dead = False
                if current_proc_to_finalize.poll() is None: # Still alive or status unknown
                    logging.warning(f"[quickdic] Process {current_proc_to_finalize.pid} (aircrack-ng for {access_point_name}) potentially alive in finally. Attempting robust kill.")
                    if self._kill_aircrack_process(current_proc_to_finalize, access_point_name):
                        logging.info(f"[quickdic] Process {current_proc_to_finalize.pid} confirmed terminated in finally block.")
                        process_confirmed_dead = True
                    else:
                        logging.error(f"[quickdic] FAILED TO KILL process {current_proc_to_finalize.pid} in finally. Cracking_in_progress will remain True.")
                        # cracking_in_progress remains True, self.aircrack_proc_handle remains assigned
                else: # Already terminated
                    logging.debug(f"[quickdic] Process {current_proc_to_finalize.pid} (aircrack-ng for {access_point_name}) confirmed already terminated upon entering finally. PID: {current_proc_to_finalize.pid}, RC: {current_proc_to_finalize.returncode}")
                    process_confirmed_dead = True
                
                if process_confirmed_dead:
                    self.cracking_in_progress = False
                    self.aircrack_proc_handle = None # Clear the handle
                # If not process_confirmed_dead, cracking_in_progress remains True and self.aircrack_proc_handle is kept.
            
            else: # current_proc_to_finalize (i.e. self.aircrack_proc_handle) is None
                  # This means Popen was never called, or failed, or it was an early exit.
                  # cracking_in_progress was set True at the start, so reset it.
                if self.cracking_in_progress: # Only log/change if it was True
                    logging.debug("[quickdic] proc object was None in finally. Setting cracking_in_progress to False as no process was actively managed to completion.")
                    self.cracking_in_progress = False
                # self.aircrack_proc_handle is already None

            # Final status log for this attempt
            if self.cracking_in_progress:
                 logging.warning(f"[quickdic] Exiting _try_crack_handshake for {access_point_name} - CRACKING_IN_PROGRESS REMAINS TRUE (PID: {self.aircrack_proc_handle.pid if self.aircrack_proc_handle else 'N/A'}).")
            else:
                 logging.debug(f"[quickdic] Exiting _try_crack_handshake for {access_point_name} - cracking_in_progress is now False.")

        logging.info(f"[quickdic] Finished cracking attempt for {access_point_name}. Result: {aircrack_return_status}")
        return aircrack_return_status

    def on_handshake(self, agent, filename, access_point, client_station):
        if not self.enabled_on_system:
            return # Do nothing if not on Linux
        
        # Current logic of on_handshake (if any) would go here.
        # This plugin primarily works by scanning existing files, but if you want
        # to trigger an immediate crack attempt on a new handshake, you could add logic here.
        # For now, we'll assume it relies on the periodic scan.
        logging.debug(f"[quickdic] on_handshake hook called for {access_point['hostname'] if access_point else 'N/A'}. Relying on periodic scan.")
        pass # Placeholder, as current logic is scan-based

    # Add similar checks to other public Pwnagotchi hook methods if they are implemented
    # e.g., on_bored, on_sad, on_ui_update, etc.
    # For brevity, only on_handshake is shown as an example.

    def _get_cpu_temperature(self):
        if not self.enabled_on_system:
            return None # Don't attempt to read temp if not on Linux
        
        # Original _get_cpu_temperature logic for Linux
        # ... (rest of the original _get_cpu_temperature method)
        # Ensure this method is robust if /sys/class/thermal/thermal_zone0/temp isn't available
        # even on Linux, though for RPi it usually is.
        try:
            with open("/sys/class/thermal/thermal_zone0/temp", "r") as f:
                temp = int(f.read().strip()) / 1000.0
            return temp
        except FileNotFoundError:
            logging.debug("[quickdic] CPU temperature file not found. Cannot get CPU temperature.")
            return None # Or a default/error indicator
        except Exception as e:
            logging.error(f"[quickdic] Error reading CPU temperature: {e}")
            return None
