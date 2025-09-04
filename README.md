# Pwnagotchi Plugins Collection

This repository contains a set of plugins for [Pwnagotchi](https://github.com/evilsocket/pwnagotchi), focused on managing, cracking, and displaying WPA handshake passwords. The plugins are designed to work together or independently, providing both UI and web-based access to cracked WiFi credentials.

---

## Plugins Overview

### `quickdic.py`
- **Purpose:** Periodically scans captured handshakes and attempts to crack them using dictionary attacks with `aircrack-ng`.
- **Features:**
  - Supports custom wordlist folders.
  - Avoids re-cracking already attempted handshakes.
  - Monitors CPU temperature to prevent overheating.
  - Handles timeouts and logs progress.
  - Stores cracked passwords in `.cracked` files in the handshakes directory.

### `display-password.py`
- **Purpose:** Displays the most recently cracked password on the Pwnagotchi display.
- **Features:**
  - Shows SSID (or BSSID) and password.
  - Supports multiple display types and orientations.
  - Reads from all `.cracked` files and `wpa-sec.cracked.potfile`.

### `cracked-list.py`
- **Purpose:** Provides a web interface listing all cracked passwords found by `quickdic.py` in the handshakes folder.
- **Features:**
  - Parses all `.cracked` files and displays SSID, BSSID, and password.
  - Searchable and mobile-friendly web UI.

### `reference plugins/wpa-sec-list.py`
- **Purpose:** Reference plugin for listing cracked passwords from `wpa-sec.cracked.potfile`.
- **Features:**
  - Web interface for viewing passwords.
  - Similar UI to `cracked-list.py`, but focused on the wpa-sec format.

---

## Installation

1. **Copy Plugins:**  
   Place the `.py` plugin files into your Pwnagotchi plugins directory (usually `/usr/local/lib/python3.7/dist-packages/pwnagotchi/plugins/` or similar).

2. **Configure Plugins:**  
   Edit your Pwnagotchi `config.toml` to enable and configure each plugin as needed.  
   Example for `quickdic`:
   ```toml
   [plugins.quickdic]
   enabled = true
   wordlist_folder = "/opt/wordlists/"
   max_cpu_temp = 80.0
   aircrack_timeout = 300
   ```

3. **Wordlists:**  
   Place your `.txt` wordlists in the folder specified by `wordlist_folder` (default: `/opt/wordlists/`).

4. **Dependencies:**  
   - `aircrack-ng` must be installed:  
     ```sh
     sudo apt-get install aircrack-ng
     ```

---

## Usage

- **Cracking:**  
  `quickdic.py` will automatically scan and crack new handshakes found in the handshakes directory.

- **Display:**  
  `display-password.py` will show the latest cracked password on the Pwnagotchi display.

- **Web UI:**  
  Access the cracked password list via the web interface provided by `cracked-list.py` or `wpa-sec-list.py`.

---

## Contributing

Pull requests and suggestions are welcome! Please open an issue to discuss any major changes.

---

## License

This project is licensed under the MIT License.
