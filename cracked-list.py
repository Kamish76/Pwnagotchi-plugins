import logging, json, os, glob, pwnagotchi
import pwnagotchi.plugins as plugins
from flask import abort, send_from_directory, render_template_string

TEMPLATE = """
{% extends "base.html" %}
{% set active_page = "crackedPasswordsList" %}
{% block title %}
    {{ title }}
{% endblock %}
{% block meta %}
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, user-scalable=0" />
{% endblock %}
{% block styles %}
{{ super() }}
    <style>
        #searchText {
            width: 100%;
        }
        table {
            table-layout: auto;
            width: 100%;
        }
        table, th, td {
            border: 1px solid;
            border-collapse: collapse;
        }
        th, td {
            padding: 15px;
            text-align: left;
        }
        @media screen and (max-width:700px) {
            table, tr, td {
                padding:0;
                border:1px solid;
            }
            table {
                border:none;
            }
            tr:first-child, thead, th {
                display:none;
                border:none;
            }
            tr {
                float: left;
                width: 100%;
                margin-bottom: 2em;
            }
            td {
                float: left;
                width: 100%;
                padding:1em;
            }
            td::before {
                content:attr(data-label);
                word-wrap: break-word;
                color: white;
                border-right:2px solid;
                width: 20%;
                float:left;
                padding:1em;
                font-weight: bold;
                margin:-1em 1em -1em -1em;
            }
        }
    </style>
{% endblock %}
{% block script %}
    var searchInput = document.getElementById("searchText");
    searchInput.onkeyup = function() {
        var filter, table, tr, td, i, txtValue;
        filter = searchInput.value.toUpperCase();
        table = document.getElementById("tableOptions");
        if (table) {
            tr = table.getElementsByTagName("tr");

            for (i = 0; i < tr.length; i++) {
                td = tr[i].getElementsByTagName("td")[0]; // Search by SSID (first column)
                if (td) {
                    txtValue = td.textContent || td.innerText;
                    if (txtValue.toUpperCase().indexOf(filter) > -1) {
                        tr[i].style.display = "";
                    }else{
                        tr[i].style.display = "none";
                    }
                }
            }
        }
    }
{% endblock %}
{% block content %}
    <input type="text" id="searchText" placeholder="Search for SSID..." title="Type in a filter">
    <table id="tableOptions">
        <tr>
            <th>SSID</th>
            <th>BSSID</th>
            <th>Password</th>
        </tr>
        {% for p in passwords %}
            <tr>
                <td data-label="SSID">{{p["ssid"]}}</td>
                <td data-label="BSSID">{{p["bssid"]}}</td>
                <td data-label="Password">{{p["password"]}}</td>
            </tr>
        {% endfor %}
    </table>
{% endblock %}
"""

class CrackedList(plugins.Plugin):
    __author__ = 'GitHub Copilot based on wpa-sec-list by neonlightning'
    __version__ = '1.0.0'
    __license__ = 'GPL3'
    __description__ = 'Lists all cracked passwords found by quickdic.py in .cracked files in the handshakes folder.'

    def __init__(self):
        self.ready = False
        self.config = None
        logging.debug("[CrackedList] Plugin created")

    def on_loaded(self):
        logging.info("[CrackedList] plugin loaded")

    def on_config_changed(self, config):
        self.config = config
        self.ready = True
        logging.info("[CrackedList] configuration loaded.")


    def on_webhook(self, path, request):
        logging.debug(f"[CrackedList] Webhook called with path: {path}")
        if not self.ready:
            logging.warning("[CrackedList] Plugin not ready")
            return "Plugin not ready", 503
        if not self.config:
            logging.warning("[CrackedList] Config not loaded")
            return "Plugin configuration not loaded", 503
        
        if 'bettercap' not in self.config or 'handshakes' not in self.config['bettercap']:
            logging.error("[CrackedList] Handshakes directory path not found in configuration.")
            return "Handshakes directory configuration missing", 500

        if path == "/" or not path:
            try:
                passwords_data = []
                unique_entries = set()
                
                handshakes_dir = self.config['bettercap']['handshakes']
                if not os.path.isdir(handshakes_dir):
                    logging.error(f"[CrackedList] Handshakes directory not found: {handshakes_dir}")
                    return f"Handshakes directory not found: {handshakes_dir}", 404

                # Look for files like <BSSID>_<ESSID>.cracked or similar patterns quickdic might use
                # For quickdic.py, the cracked passwords are typically stored in files named like <BSSID>.cracked
                # or <ESSID>.cracked, or <BSSID>_<ESSID>.cracked, containing "BSSID:Password:ESSID" or "ESSID:Password"
                # We will assume a common format where the file itself might be named after BSSID or ESSID
                # and the content has a parseable structure.
                # quickdic.py output format is typically BSSID:Password:ESSID or just Password if in a specific ESSID context file.
                # Let's be flexible and try to parse lines that contain at least BSSID, SSID, and Password.
                # A common output for cracked files is BSSID:HEXKEY:SSID:Password or BSSID:SSID:Password

                cracked_files_pattern = os.path.join(handshakes_dir, '*.cracked')
                cracked_files = glob.glob(cracked_files_pattern)
                logging.info(f"[CrackedList] Searching for cracked files with pattern: {cracked_files_pattern}")
                logging.info(f"[CrackedList] Found cracked files: {cracked_files}")

                for file_path in cracked_files:
                    logging.debug(f"[CrackedList] Processing file: {file_path}")
                    filename = os.path.basename(file_path)
                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            for line_number, line in enumerate(f, 1):
                                line = line.strip()
                                if not line:
                                    continue
                                
                                parts = line.split(':')
                                bssid, ssid, password_val = None, None, None

                                if filename == 'wpa-sec.cracked.potfile':
                                    if len(parts) >= 4: # BSSID:HEXKEY:SSID:Password
                                        bssid = parts[0]
                                        ssid = parts[2]
                                        password_val = parts[3]
                                    else:
                                        logging.warning(f"[CrackedList] Malformed line in {filename} (line {line_number}): {line}")
                                        continue
                                else: # Other *.cracked files
                                    if len(parts) == 3:
                                        if len(parts[0]) == 17 and parts[0].count(':') == 5: # BSSID:Password:SSID
                                            bssid, password_val, ssid = parts[0], parts[1], parts[2]
                                        elif len(parts[2]) == 17 and parts[2].count(':') == 5: # SSID:Password:BSSID
                                            ssid, password_val, bssid = parts[0], parts[1], parts[2]
                                        else:
                                            logging.warning(f"[CrackedList] Unrecognized 3-part format in {filename} (line {line_number}): {line}")
                                            continue
                                    elif len(parts) >= 4: # BSSID:ANY_FIELD:SSID:Password (common fallback)
                                        bssid = parts[0]
                                        ssid = parts[2]
                                        password_val = parts[3]
                                    elif len(parts) == 1 and parts[0]: # Single field, assume it's a password
                                        password_val = parts[0]
                                        # Try to use filename (sans ext) as SSID, if not BSSID-like
                                        fn_name_part, _ = os.path.splitext(filename)
                                        if not (len(fn_name_part) == 17 and fn_name_part.count(':') == 5):
                                            ssid = fn_name_part
                                            logging.info(f"[CrackedList] Used filename '{ssid}' as SSID for password-only line in {filename} (line {line_number})")
                                        else: # Filename looks like a BSSID, don't use as SSID here. Password only.
                                            logging.info(f"[CrackedList] Password-only line in {filename} (line {line_number}), filename is BSSID-like, SSID unknown.")
                                            # We need an SSID or BSSID for the table, so this might not be ideal unless we default one.
                                            # For now, if only password, we might skip or assign a placeholder.
                                            # Let's require at least an SSID or BSSID for the table.
                                            if not ssid and not bssid: # If we couldn't infer SSID and no BSSID
                                                logging.warning(f"[CrackedList] Password-only line in {filename} (line {line_number}) without inferable SSID/BSSID. Skipping: {line}")
                                                continue
                                    else:
                                        logging.warning(f"[CrackedList] Malformed/unhandled line in {filename} (line {line_number}): {line}")
                                        continue
                                
                                if password_val and (ssid or bssid): # Ensure we have a password and at least one identifier
                                    # Basic validation for BSSID format if present
                                    if bssid and not (len(bssid) == 17 and bssid.count(':') == 5):
                                        logging.warning(f"[CrackedList] Invalid BSSID format '{bssid}' in {filename} (line {line_number}): {line}. Attempting to use as SSID if SSID is missing.")
                                        if not ssid: # If original SSID was none, and BSSID is malformed, maybe it was meant to be an SSID
                                            ssid = bssid # Try using the malformed bssid as an ssid
                                        bssid = "N/A" # Mark BSSID as N/A
                                    
                                    # Ensure SSID and BSSID are strings, default to "N/A" if None
                                    current_ssid = ssid if ssid else "N/A"
                                    current_bssid = bssid.upper() if bssid else "N/A"

                                    entry_tuple = (current_bssid, current_ssid, password_val)
                                    if entry_tuple not in unique_entries:
                                        unique_entries.add(entry_tuple)
                                        logging.debug(f"[CrackedList] Added entry: {entry_tuple}")
                                    else:
                                        logging.debug(f"[CrackedList] Duplicate entry skipped: {entry_tuple}")
                                else:
                                    logging.warning(f"[CrackedList] Could not parse essential data (Password and SSID/BSSID) from line in {filename} (line {line_number}): {line}")
                                    
                    except Exception as e:
                        logging.error(f"[CrackedList] Error reading file {file_path}: {e}")
                        logging.debug(e, exc_info=True)

                # Sort unique entries by SSID (the second element in the tuple), case-insensitive
                # then by BSSID (the first element)
                sorted_entries = sorted(list(unique_entries), key=lambda x: (x[1].lower(), x[0].lower()))

                for bssid_val, ssid_val, pass_val in sorted_entries: # Renamed to avoid conflict
                    passwords_data.append({
                        "ssid": ssid_val,
                        "bssid": bssid_val,
                        "password": pass_val
                    })
                
                logging.info(f"[CrackedList] Rendering template with {len(passwords_data)} passwords.")
                return render_template_string(TEMPLATE,
                                        title="Quickdic Cracked Passwords",
                                        passwords=passwords_data)
            except Exception as e:
                logging.error(f"[CrackedList] Error processing request: {e}")
                logging.debug(e, exc_info=True)
                return "Internal server error", 500
        else:
            logging.debug(f"[CrackedList] Path not found: {path}")
            return "Not Found", 404

