# Palo Alto Firewall Analyzer

![Build](github.com/moshekaplan/palo_alto_firewall_analyzer/workflows/build/badge.svg)

Scripts for reviewing and suggesting fixes for Palo Alto Firewall configurations

This repository contains the following two scripts:

* `pan_policy_validator.py` - Detects Palo Alto Network firewall configuration issues
* `pan_policy_fixer.py` - Fixes detected Palo Alto Network firewall configuration issues

## Quickstart

1. Modify `PAN_CONFIG.cfg` with your panorama's hostname and version number.
1. The first time you launch the validator, it will check for a file
"API_KEY.txt", with your API key. If "API_KEY.txt" is not present, the script will
prompt for credentials and save the retrieved API key to "API_KEY.txt"

Run a single validator on a single device groups:
`pan_policy_validator.py --device-group my_device_group --validator UnusedServices`

Run a single validator on all device groups:
`pan_policy_validator.py --all --validator UnusedServices`

Run all validators on all device groups (this may take a long time):
`pan_policy_validator.py --all`

## License ##

This project is in the worldwide [public domain](LICENSE).

This project is in the public domain within the United States, and
copyright and related rights in the work worldwide are waived through
the [CC0 1.0 Universal public domain
dedication](https://creativecommons.org/publicdomain/zero/1.0/).

All contributions to this project will be released under the CC0
dedication. By submitting a pull request, you are agreeing to comply
with this waiver of copyright interest.
