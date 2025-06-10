import pwnagotchi.plugins as plugins
import logging
import os
import glob
import threading
import subprocess
import string
import pwnagotchi # Added for pwnagotchi.config access
import time # Added for time.time()
import select # Added for select.select()

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
CRACK_PREVENTED = "CRACK_PREVENTED"

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
        logging.debug(f"[quickdic] __init__: current_status = {self.current_status}")

    def on_loaded(self):
        logging.info(f"Quick dictionary check plugin loaded (v{self.__version__})")

        # Define defaults for actual configurable options
        plugin_specific_defaults = {
            'wordlist_folder': '/opt/wordlists/',
            'max_cpu_temp': 80.0,
            'aircrack_timeout': 300
        }
        
        # Allow Pwnagotchi to load values from config.toml into self.options
        # The base class on_loaded() populates self.options from the config file.
        # We need to ensure our defaults are used if options are missing or invalid.
        # super().on_loaded() might replace self.options entirely or merge.
        # For safety, we'll process after calling it.

        # Store a reference to config-loaded options if Pwnagotchi populated it
        config_loaded_options = self.options.copy() if isinstance(self.options, dict) else {}

        if hasattr(super(), 'on_loaded'):
             super().on_loaded() # This call might modify self.options

        # Consolidate options: Start with plugin defaults, then override with config values if present and valid.
        # Pwnagotchi's plugin loader usually handles loading config into self.options.
        # We just need to ensure our expected keys are present and correctly typed.
        processed_options = {}
        for key, default_value in plugin_specific_defaults.items():
            # Use the value from self.options (potentially loaded from config.toml by super().on_loaded())
            # or fall back to the value that was in self.options before super().on_loaded() if it was a dict
            # or finally, use our hardcoded default.
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
        logging.info("[quickdic] Periodic scan loop initiated.")
        
        try:
            self._stop_event.wait(5) # Initial delay before first scan
            while not self._stop_event.is_set():
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
        
        logging.info(f"[quickdic] [{thread_name}] Plugin unloaded.")

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
        logging.info(f"[quickdic] Attempting to crack: {access_point_name} from file: {pcap_filepath}")
        self.current_status = STATUS_CRACKING

        if self.cracking_in_progress:
            logging.info(f"[quickdic] Another cracking process is already running. Skipping {access_point_name} for now.")
            return CRACK_PREVENTED

        self.cracking_in_progress = True

        max_temp = float(self.options.get('max_cpu_temp', 80.0))
        timeout_seconds = int(self.options.get('aircrack_timeout', 300))
        wordlist_folder = self.options.get('wordlist_folder', '/opt/wordlists/')
        
        current_temp = self._get_cpu_temperature()
        if current_temp is not None and current_temp > max_temp:
            logging.warning(f"[quickdic] CPU temp ({current_temp:.1f}°C) > limit ({max_temp}°C). Skipping {access_point_name}.")
            self.current_status = STATUS_CPU_HOT
            self.cracking_in_progress = False
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
            self.cracking_in_progress = False
            return CRACK_ERROR
        except Exception as e:
            logging.error(f"[quickdic] Error during handshake check for {pcap_filepath}: {e}", exc_info=True)
            self.current_status = STATUS_HANDSHAKE_VERIFY_FAIL
            self.cracking_in_progress = False
            return CRACK_ERROR

        if not bssid_result:
            logging.info(f"[quickdic] No handshake confirmed in {pcap_filepath}.")
            self.current_status = STATUS_HANDSHAKE_VERIFY_FAIL
            self.cracking_in_progress = False
            return CRACK_ERROR
        
        wordlist_files = glob.glob(os.path.join(wordlist_folder, "*.txt"))
        if not wordlist_files:
            logging.warning(f"[quickdic] No .txt wordlists found in {wordlist_folder}.")
            self.current_status = STATUS_NO_WORDLISTS
            self.cracking_in_progress = False
            return CRACK_ERROR

        wordlist_argument_string = ','.join(f'"{w}"' for w in wordlist_files)
        cracked_file_output_path = f"{pcap_filepath}.cracked"
        # Corrected aircrack_cmd_str to avoid issues with quotes and f-string formatting within shell command
        aircrack_cmd_str = f'''aircrack-ng -w {wordlist_argument_string} -l "{cracked_file_output_path}" -q -b {bssid_result} "{pcap_filepath}"'''
        
        aircrack_return_status = CRACK_ERROR 
        proc = None
        try:
            proc = subprocess.Popen(aircrack_cmd_str, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, bufsize=1, preexec_fn=os.setsid if os.name != 'nt' else None)
            key_found_and_processed = False
            start_time = time.time()

            while not key_found_and_processed:
                elapsed_time = time.time() - start_time
                if elapsed_time > timeout_seconds:
                    logging.info(f"[quickdic] Aircrack-ng timed out for {access_point_name}.")
                    self.current_status = STATUS_TIMEOUT
                    aircrack_return_status = CRACK_ERROR
                    break 
                if proc.poll() is not None: break 

                ready_to_read, _, _ = select.select([proc.stdout, proc.stderr], [], [], 0.5)
                for stream in ready_to_read:
                    line = stream.readline()
                    if not line: continue
                    line_strip = line.strip()
                    logging.debug(f"[quickdic] aircrack-ng output: {line_strip}") 
                    if stream is proc.stdout and "KEY FOUND!" in line_strip:
                        try:
                            key = line_strip.split('[')[1].split(']')[0].strip()
                            logging.info(f"[quickdic] KEY FOUND for {access_point_name}: {key}")
                            self.current_status = STATUS_CRACKED
                            aircrack_return_status = CRACK_SUCCESS
                            key_found_and_processed = True
                            break 
                        except IndexError:
                            logging.error(f"[quickdic] Could not parse KEY FOUND line: {line_strip}")
                    elif stream is proc.stderr and line_strip: 
                        if "Resetting EAPOL Handshake decoder state." in line_strip:
                            logging.debug(f"[quickdic] aircrack-ng stderr: {line_strip}") # Log this specific message at DEBUG
                        else:
                            logging.warning(f"[quickdic] aircrack-ng stderr: {line_strip}") # Log other stderr as WARNING

                if key_found_and_processed: break
            
            if proc.poll() is None:
                logging.info(f"[quickdic] Terminating aircrack-ng process for {access_point_name} (PID: {{proc.pid}}).")
                try:
                    if os.name != 'nt': 
                        os.killpg(os.getpgid(proc.pid), subprocess.signal.SIGTERM)
                    else: 
                        proc.terminate()
                    proc.wait(timeout=5)
                except ProcessLookupError:
                    logging.warning(f"[quickdic] Process {{proc.pid}} already terminated.")
                except Exception as e:
                    logging.error(f"[quickdic] Error terminating aircrack-ng process {{proc.pid}}: {{e}}")

            # Drain remaining output if key not yet found
            if not key_found_and_processed:
                logging.debug(f"[quickdic] Final check of aircrack-ng output for {{access_point_name}}.")
                # Drain stdout
                try:
                    for line in proc.stdout: 
                        line_strip = line.strip()
                        if not line_strip: continue # Skip empty lines
                        logging.debug(f"[quickdic] aircrack-ng remaining stdout: {{line_strip}}")
                        if "KEY FOUND!" in line_strip:
                            try:
                                key = line_strip.split('[')[1].split(']')[0].strip()
                                logging.info(f"[quickdic] KEY FOUND (in final check) for {{access_point_name}}: {{key}}")
                                self.current_status = STATUS_CRACKED
                                aircrack_return_status = CRACK_SUCCESS
                                key_found_and_processed = True
                                break # Key found in stdout, stop draining stdout
                            except IndexError:
                                logging.error(f"[quickdic] Could not parse KEY FOUND line from final check: {{line_strip}}")
                except Exception as e_stdout_drain:
                    logging.debug(f"[quickdic] Exception during final stdout check for {{access_point_name}}: {{e_stdout_drain}}")
                
                # Drain stderr for logging (useful for diagnostics)
                try:
                    for line in proc.stderr:
                        line_strip = line.strip()
                        if not line_strip: continue # Skip empty lines
                        # Log all remaining stderr
                        if "Resetting EAPOL Handshake decoder state." in line_strip:
                            logging.debug(f"[quickdic] aircrack-ng remaining stderr: {{line_strip}}")
                        else:
                            logging.warning(f"[quickdic] aircrack-ng remaining stderr: {{line_strip}}")
                except Exception as e_stderr_drain:
                    logging.debug(f"[quickdic] Exception during final stderr check for {{access_point_name}}: {{e_stderr_drain}}")

            if not key_found_and_processed and aircrack_return_status != CRACK_SUCCESS:
                 if proc.poll() is not None and elapsed_time < timeout_seconds :
                    logging.info(f"[quickdic] Key not found by aircrack-ng for {{access_point_name}}.")
                    self.current_status = STATUS_NOT_FOUND_SCAN
                    aircrack_return_status = CRACK_NOT_FOUND
                 elif elapsed_time > timeout_seconds and aircrack_return_status != CRACK_ERROR: 
                    self.current_status = STATUS_TIMEOUT
                    aircrack_return_status = CRACK_ERROR


        except FileNotFoundError:
            logging.error(f"[quickdic] aircrack-ng command not found. Ensure it is installed and in PATH.")
            self.current_status = STATUS_AIRCRACK_FAIL
            aircrack_return_status = CRACK_ERROR
        except Exception as e:
            logging.error(f"[quickdic] General error running aircrack-ng for {access_point_name}: {e}", exc_info=True)
            self.current_status = STATUS_ERROR
            aircrack_return_status = CRACK_ERROR
        finally:
            if proc:
                if proc.stdout: proc.stdout.close()
                if proc.stderr: proc.stderr.close()
            self.cracking_in_progress = False

        logging.info(f"[quickdic] Finished cracking attempt for {access_point_name}. Result: {aircrack_return_status}")
        return aircrack_return_status

    def _get_cpu_temperature(self):
        """Reads CPU temperature."""
        # This implementation is for Raspberry Pi.
        # For other systems, this method might need adjustment or return None.
        temp_file = '/sys/class/thermal/thermal_zone0/temp'
        if os.path.exists(temp_file):
            try:
                with open(temp_file, 'r') as f:
                    return float(f.read()) / 1000.0
            except Exception as e:
                logging.warning(f"[quickdic] Could not read CPU temperature from {temp_file}: {e}")
                return None
        else:
            # Attempt to use 'vcgencmd' as a fallback for Raspberry Pi if /sys/class/thermal is not available
            try:
                temp_str = subprocess.check_output(['vcgencmd', 'measure_temp'], universal_newlines=True) # Example: temp=53.5'C
                temp_val = temp_str.split('=')[1].split('\'')[0]
                return float(temp_val)
            except FileNotFoundError:
                logging.debug("[quickdic] vcgencmd not found. Cannot get CPU temperature.")
                return None
            except Exception as e:
                logging.warning(f"[quickdic] Could not read CPU temperature using vcgencmd: {e}")
                return None
