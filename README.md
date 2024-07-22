# otp_manager

OTP Manager is a command-line tool for managing and generating One-Time Passwords (OTPs) for various services.

The idea is based on [bash-otp](https://github.com/poolpog/bash-otp), but with a different approach.

Features:
* Automatic copy to clipboard
* Aegis Authenticator Backup Support
* Private and offline
* Interactive mode with fuzzy finding

Features that will be available in the next updates:
- [ ] Encrypted backups
- [ ] User defined unlock time
- [ ] QR Code export

## How to use

Clone the repo and install the package:
```bash
git clone https://github.com/Lorenzoantonelli/otp_manager.git
pip install .
```

To use the interactive mode install [gum](https://github.com/charmbracelet/gum).

Unlock it for the first time to set the master password:
```bash
otp-manager --unlock
```

## Usage
```
usage: otp-manager [-h]
               (-u | -l | -a SERVICE | -d SERVICE | -g [SERVICE] | -ls | -i FILE | -r OLD_NAME NEW_NAME)
               [-s SECRET] [--digits DIGITS] [--interval INTERVAL] [-c]

OTP Manager

options:
  -h, --help            show this help message and exit
  -u, --unlock          Unlock the OTP manager
  -l, --lock            Lock the OTP manager
  -a SERVICE, --add SERVICE
                        Add a new secret
  -d SERVICE, --delete SERVICE
                        Delete a secret
  -g [SERVICE], --generate [SERVICE]
                        Generate OTP for a service. If no service is provided,
                        enter interactive mode.
  -ls, --list           List all services
  -i FILE, --import FILE
                        Import secrets from Aegis JSON file
  -r OLD_NAME NEW_NAME, --rename OLD_NAME NEW_NAME
                        Rename a service
  -s SECRET, --secret SECRET
                        Secret value for adding or updating
  --digits DIGITS       Number of digits for OTP (default: 6)
  --interval INTERVAL   Time interval for OTP in seconds (default: 30)
  -c, --copy            Copy generated OTP to clipboard
```

## Examples
### Add a new service
```bash
otp-manager -a my_new_service
```

### Generate the OTP for a service
```bash
otp-manager -g my_new_service
```

