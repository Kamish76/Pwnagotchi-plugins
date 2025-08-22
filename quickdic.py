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
    __version__ = '1.3.0'
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
                    # Increased wait interval to 30s to reduce CPU usage
                    self._stop_event.wait(30)
                if self._stop_event.is_set():
                    break
                if self.main_config_for_scan and \
                   self.current_status != STATUS_NO_WORDLISTS and \
                   self.current_status != STATUS_AIRCRACK_FAIL:
                    self.current_status = STATUS_SCANNING
                    self._scan_and_crack_existing(self.main_config_for_scan)
                    if self.current_status not in [STATUS_ERROR, STATUS_CPU_HOT]:
                        self.current_status = STATUS_IDLE
                else:
                    if not self.main_config_for_scan:
                        logging.warning("[quickdic] Main config not available for periodic scan. Loop paused.")
                    self._stop_event.wait(60)
                    if not self.main_config_for_scan and hasattr(pwnagotchi, 'config') and 'main' in pwnagotchi.config:
                        self.main_config_for_scan = pwnagotchi.config['main'].get('bettercap', {}).get('handshakes_path') and pwnagotchi.config['main']
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
            
        self.current_status = STATUS_SCANNING
        # Batch file checks: build sets of already processed files
        all_pcap_files = set(glob.glob(os.path.join(handshakes_path, "*.pcap")))
        already_cracked = set(f[:-8] for f in glob.glob(os.path.join(handshakes_path, "*.pcap.cracked")))
        already_failed = set(f[:-16] for f in glob.glob(os.path.join(handshakes_path, "*.pcap.quickdic_failed")))
        files_to_process = [f for f in all_pcap_files if f not in already_cracked and f not in already_failed]
        if not files_to_process:
            logging.info("[quickdic] No new handshakes to process in this pass.")
            return
        # Efficient wordlist handling: cache wordlist list for this scan pass
        wordlist_folder = self.options.get('wordlist_folder', '/opt/wordlists/')
        wordlist_files = glob.glob(os.path.join(wordlist_folder, "*.txt"))
        for pcap_file in files_to_process:
            if self._stop_event.is_set():
                break
            base_filename = os.path.basename(pcap_file)
            essid_from_filename = base_filename.split('_')[0] if '_' in base_filename else base_filename.replace(".pcap", "")
            crack_result = self._try_crack_handshake(pcap_file, essid_from_filename, wordlist_files=wordlist_files)
            if crack_result == CRACK_NOT_FOUND or crack_result == CRACK_ERROR:
                failed_marker_filepath = pcap_file + ".quickdic_failed"
                try:
                    with open(failed_marker_filepath, 'w') as f:
                        pass
                except Exception as e:
                    logging.error(f"[quickdic] Could not create failed marker {failed_marker_filepath}: {e}")
            if self._stop_event.is_set():
                break
            self._stop_event.wait(5)

    def _try_crack_handshake(self, pcap_filepath, access_point_name, wordlist_files=None):
        if not self.enabled_on_system:
            logging.warning(f"[quickdic] Plugin disabled on this system. Skipping crack attempt for {access_point_name}.")
            return CRACK_PREVENTED
        if self.cracking_in_progress:
            return CRACK_PREVENTED
        self.cracking_in_progress = True
        self.current_status = STATUS_CRACKING
        if self.aircrack_proc_handle is not None:
            self.aircrack_proc_handle = None
        max_temp = float(self.options.get('max_cpu_temp', 80.0))
        timeout_seconds = int(self.options.get('aircrack_timeout', 300))
        # Conditional temperature check: only here
        current_temp = self._get_cpu_temperature()
        if current_temp is not None and current_temp > max_temp:
            self.current_status = STATUS_CPU_HOT
            self.cracking_in_progress = False
            return CRACK_PREVENTED
        # Properly escape awk braces in f-string
        handshake_check_cmd = f'/usr/bin/aircrack-ng "{pcap_filepath}" | grep "1 handshake"'
        bssid_result = ""
        try:
            result_proc = subprocess.run(handshake_check_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, timeout=30)
            handshake_line = result_proc.stdout.strip()
            logging.debug(f"[quickdic] Handshake check output for {pcap_filepath}: {handshake_line}")
            import re
            # Extract BSSID using regex (matches MAC address at start of line)
            match = re.search(r'([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})', handshake_line)
            if match:
                bssid_result = match.group(1)
            else:
                bssid_result = ""
        except subprocess.TimeoutExpired:
            self.current_status = STATUS_HS_TIMEOUT
            self.cracking_in_progress = False
            return CRACK_ERROR
        except Exception:
            self.current_status = STATUS_HANDSHAKE_VERIFY_FAIL
            self.cracking_in_progress = False
            return CRACK_ERROR
        if not bssid_result:
            self.current_status = STATUS_HANDSHAKE_VERIFY_FAIL
            self.cracking_in_progress = False
            return CRACK_ERROR
        # Use cached wordlist_files if provided
        if wordlist_files is None:
            wordlist_folder = self.options.get('wordlist_folder', '/opt/wordlists/')
            wordlist_files = glob.glob(os.path.join(wordlist_folder, "*.txt"))
        if not wordlist_files:
            self.current_status = STATUS_NO_WORDLISTS
            self.cracking_in_progress = False
            return CRACK_ERROR
        wordlist_argument_string = ','.join(f'"{w}"' for w in wordlist_files)
        cracked_file_output_path = f"{pcap_filepath}.cracked"
        # Limit subprocess resource usage: use nice and ionice
        base_aircrack_cmd = f'nice -n 10 ionice -c3 aircrack-ng -w {wordlist_argument_string} -l "{cracked_file_output_path}" -q -b {bssid_result} "{pcap_filepath}"'
        if os.name != 'nt':
            aircrack_cmd_str = f'timeout {timeout_seconds}s {base_aircrack_cmd}'
        else:
            aircrack_cmd_str = base_aircrack_cmd
        local_proc_handle = None
        aircrack_return_status = CRACK_ERROR
        try:
            # Reduce logging: only log command at info level
            logging.info(f"[quickdic] Executing aircrack-ng: {aircrack_cmd_str}")
            local_proc_handle = subprocess.Popen(aircrack_cmd_str, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, 
                                    universal_newlines=True, preexec_fn=os.setsid if os.name != 'nt' else None)
            self.aircrack_proc_handle = local_proc_handle
            stdout_data, stderr_data = "", ""
            try:
                stdout_data, stderr_data = local_proc_handle.communicate(timeout=timeout_seconds)
                # Only log warnings/errors, not all output
                if stderr_data:
                    for line in stderr_data.strip().splitlines():
                        if ("No networks found, exiting." in line or
                            "Please specify a dictionary" in line or
                            ("Opening" in line and "failed: No such file or directory" in line) or
                            "Unsupported KDF type" in line or
                            "No valid WPA handshakes found" in line):
                            continue
                        elif "Read error: Broken pipe" in line:
                            continue
                        else:
                            logging.warning(f"[quickdic] aircrack-ng stderr: {line.strip()}")
                if os.path.exists(cracked_file_output_path):
                    self.current_status = STATUS_CRACKED
                    aircrack_return_status = CRACK_SUCCESS
                else:
                    if local_proc_handle.returncode != 0:
                        aircrack_return_status = CRACK_ERROR
                    else:
                        aircrack_return_status = CRACK_NOT_FOUND
            except subprocess.TimeoutExpired:
                self.current_status = STATUS_TIMEOUT
                aircrack_return_status = CRACK_ERROR
                if local_proc_handle and local_proc_handle.poll() is None:
                    self._kill_aircrack_process(local_proc_handle, access_point_name)
        except FileNotFoundError:
            self.current_status = STATUS_AIRCRACK_FAIL
            aircrack_return_status = CRACK_ERROR
        except Exception:
            self.current_status = STATUS_ERROR
            aircrack_return_status = CRACK_ERROR
        finally:
            current_proc_to_finalize = self.aircrack_proc_handle
            if current_proc_to_finalize:
                if current_proc_to_finalize.stdout and not current_proc_to_finalize.stdout.closed:
                    current_proc_to_finalize.stdout.close()
                if current_proc_to_finalize.stderr and not current_proc_to_finalize.stderr.closed:
                    current_proc_to_finalize.stderr.close()
                process_confirmed_dead = False
                if current_proc_to_finalize.poll() is None:
                    if self._kill_aircrack_process(current_proc_to_finalize, access_point_name):
                        process_confirmed_dead = True
                else:
                    process_confirmed_dead = True
                if process_confirmed_dead:
                    self.cracking_in_progress = False
                    self.aircrack_proc_handle = None
            else:
                if self.cracking_in_progress:
                    self.cracking_in_progress = False
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
