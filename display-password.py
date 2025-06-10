from pwnagotchi.ui.components import LabeledValue
from pwnagotchi.ui.view import BLACK
import pwnagotchi.ui.fonts as fonts
import pwnagotchi.plugins as plugins
import pwnagotchi
import logging
import os
import glob # Added for finding files
import time # Added for time-based execution


class DisplayPassword(plugins.Plugin):
    __author__ = 'Kamish (updated by GitHub Copilot)'
    __version__ = '1.1.0'
    __license__ = 'GPL3'
    __description__ = 'A plugin to display the most recently cracked password on the pwnagotchi display. It checks wpa-sec.cracked.potfile and other .cracked files in the handshakes directory.'

    def on_loaded(self):
        logging.info("display-password loaded")
        self.last_check_time = 0
        self.last_displayed_password_info_str = "" # To compare with new info
        self.config = {} # Will be populated by on_config_changed
        logging.debug("DisplayPassword: Plugin loaded and attributes initialized.")

    def on_config_changed(self, config):
        self.config = config
        logging.info("DisplayPassword: Configuration updated.")
        # Force a check on next UI update if config changes, by resetting last_check_time
        self.last_check_time = 0

    def on_ui_setup(self, ui):
        if ui.is_waveshare_v2():
            h_pos = (0, 95)
            v_pos = (180, 61)
        elif ui.is_waveshare_v4():
            h_pos = (0, 95)
            v_pos = (180, 61)
        elif ui.is_waveshare_v3():
            h_pos = (0, 95)
            v_pos = (180, 61)  
        elif ui.is_waveshare_v1():
            h_pos = (0, 95)
            v_pos = (170, 61)
        elif ui.is_waveshare144lcd():
            h_pos = (0, 92)
            v_pos = (78, 67)
        elif ui.is_inky():
            h_pos = (0, 83)
            v_pos = (165, 54)
        elif ui.is_waveshare27inch():
            h_pos = (0, 153)
            v_pos = (216, 122)
        else:
            h_pos = (0, 91)
            v_pos = (180, 61)

        if self.options['orientation'] == "vertical":
            ui.add_element('display-password', LabeledValue(color=BLACK, label='', value='',
                                                   position=v_pos,
                                                   label_font=fonts.Bold, text_font=fonts.Small))
        else:
            # default to horizontal
            ui.add_element('display-password', LabeledValue(color=BLACK, label='', value='',
                                                   position=h_pos,
                                                   label_font=fonts.Bold, text_font=fonts.Small))

    def on_unload(self, ui):
        with ui._lock:
            ui.remove_element('display-password')

    def on_ui_update(self, ui):
        current_time = time.time()
        # Allow immediate check if last_check_time is 0 (e.g., after config change or load)
        if self.last_check_time != 0 and (current_time - self.last_check_time < 30):  # Check every 30s
            return
        self.last_check_time = current_time
        logging.debug("DisplayPassword: Starting UI update check.")

        if not self.config:
            logging.warning("DisplayPassword: Config not available yet.")
            # Do not update UI to prevent "Cfg err" from flashing if config is just loading
            return

        handshakes_dir = self.config.get('bettercap', {}).get('handshakes')
        if not handshakes_dir:
            logging.error("DisplayPassword: Handshakes directory not configured (bettercap.handshakes).")
            if self.last_displayed_password_info_str != 'Cfg err: HS dir':
                ui.set('display-password', 'Cfg err: HS dir')
                self.last_displayed_password_info_str = 'Cfg err: HS dir'
            return

        if not os.path.isdir(handshakes_dir):
            logging.error(f"DisplayPassword: Configured handshakes directory '{handshakes_dir}' not found.")
            if self.last_displayed_password_info_str != 'Dir err: HS dir':
                ui.set('display-password', 'Dir err: HS dir')
                self.last_displayed_password_info_str = 'Dir err: HS dir'
            return

        latest_file_mtime = 0
        candidate_info = None  # Stores {"ssid": ..., "password": ..., "bssid": ..., "filename": ...}
        
        cracked_files_pattern = os.path.join(handshakes_dir, '*.cracked')
        all_cracked_files = glob.glob(cracked_files_pattern)
        logging.debug(f"DisplayPassword: Found cracked files: {all_cracked_files}")

        if not all_cracked_files:
            if self.last_displayed_password_info_str != 'No cracked files':
                ui.set('display-password', 'No cracked files')
                self.last_displayed_password_info_str = 'No cracked files'
                logging.info("DisplayPassword: Display set to 'No cracked files'.")
            return

        for file_path in all_cracked_files:
            try:
                mtime = os.path.getmtime(file_path)
                if mtime > latest_file_mtime:
                    logging.debug(f"DisplayPassword: Processing newer file {file_path} with mtime {mtime}.")
                    last_line_content = None
                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            lines = f.readlines()
                            if lines:
                                last_line_content = lines[-1].strip()
                    except Exception as e_read:
                        logging.warning(f"DisplayPassword: Could not read last line from {file_path}: {e_read}")
                        continue

                    if last_line_content:
                        bssid, ssid, password = None, None, None
                        parts = last_line_content.split(':')
                        filename = os.path.basename(file_path)

                        if filename == 'wpa-sec.cracked.potfile':
                            if len(parts) >= 4: # BSSID:HEXKEY:SSID:Password
                                bssid = parts[0]
                                ssid = parts[2]
                                password = parts[3]
                            else:
                                logging.warning(f"DisplayPassword: Malformed line in {filename}: {last_line_content}")
                        else: # Other *.cracked files
                            if len(parts) == 3:
                                if len(parts[0]) == 17 and parts[0].count(':') == 5: # BSSID:Password:SSID
                                    bssid, password, ssid = parts[0], parts[1], parts[2]
                                elif len(parts[2]) == 17 and parts[2].count(':') == 5: # SSID:Password:BSSID
                                    ssid, password, bssid = parts[0], parts[1], parts[2]
                                else:
                                    logging.warning(f"DisplayPassword: Unrecognized 3-part format in {filename}: {last_line_content}")
                            elif len(parts) >= 4: # BSSID:ANY_FIELD:SSID:Password (common fallback)
                                bssid = parts[0]
                                ssid = parts[2]
                                password = parts[3]
                            elif len(parts) == 1 and parts[0]: # Single field, assume it's a password
                                password = parts[0]
                                # Try to use filename (sans ext) as SSID, if not BSSID-like
                                fn_name_part, _ = os.path.splitext(filename)
                                if not (len(fn_name_part) == 17 and fn_name_part.count(':') == 5):
                                    ssid = fn_name_part
                                    logging.info(f"DisplayPassword: Used filename '{ssid}' as SSID for password-only line in {filename}")
                                else: # Filename looks like a BSSID, don't use as SSID here. Password only.
                                    logging.info(f"DisplayPassword: Password-only line in {filename}, filename is BSSID-like, SSID unknown.")
                            else:
                                logging.warning(f"DisplayPassword: Malformed/unhandled line in {filename}: {last_line_content}")
                        
                        if password and (ssid or bssid):
                            latest_file_mtime = mtime
                            candidate_info = {"ssid": ssid, "password": password, "bssid": bssid, "filename": filename}
                            logging.debug(f"DisplayPassword: New candidate from {filename}: SSID={ssid}, BSSID={bssid}, Pass={password[:5]}...")
                        elif password and not (ssid or bssid): # Password found, but no clear identifier from line
                             logging.warning(f"DisplayPassword: Password found in {filename} but no SSID/BSSID from line: {last_line_content}")


            except OSError as e_os:
                logging.warning(f"DisplayPassword: Could not get mtime/process file {file_path}: {e_os}")
            except Exception as e_gen:
                logging.error(f"DisplayPassword: General error processing file {file_path}: {e_gen}", exc_info=True)
        
        final_display_message = ""
        if candidate_info:
            display_ssid = candidate_info.get("ssid")
            display_bssid = candidate_info.get("bssid")
            display_password = candidate_info.get("password", "") # Ensure password is not None

            display_identifier = ""
            max_identifier_len = 16 # Max length for SSID/BSSID part
            
            if display_ssid:
                display_identifier = display_ssid[:max_identifier_len] + ('..' if len(display_ssid) > max_identifier_len else '')
            elif display_bssid: # Fallback to BSSID if SSID is missing
                display_identifier = display_bssid # BSSID is fixed length, should fit
            else:
                display_identifier = "N/A" # Should ideally not happen if candidate_info is valid

            max_pass_len = 16 # Max length for password part
            display_pass_str = display_password[:max_pass_len] + ('..' if len(display_password) > max_pass_len else '')
            
            final_display_message = f"{display_identifier} | {display_pass_str}"
        
        if final_display_message:
            if self.last_displayed_password_info_str != final_display_message:
                ui.set('display-password', final_display_message)
                self.last_displayed_password_info_str = final_display_message
                logging.info(f"DisplayPassword: Updated display to: {final_display_message} (from {candidate_info['filename'] if candidate_info else 'N/A'})")
        else: # No valid candidate_info found from any file
            if all_cracked_files: # Files exist, but no usable recent password
                if self.last_displayed_password_info_str != 'No recent PWD':
                    ui.set('display-password', 'No recent PWD')
                    self.last_displayed_password_info_str = 'No recent PWD'
                    logging.info("DisplayPassword: Display set to 'No recent PWD'.")
            # This case should be covered by the check at the beginning of the loop
            # else: 
            #     if self.last_displayed_password_info_str != 'No cracked files':
            #         ui.set('display-password', 'No cracked files')
            #         self.last_displayed_password_info_str = 'No cracked files'
            #         logging.info("DisplayPassword: Display set to 'No cracked files' (fallback).")
