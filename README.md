# Palo Alto Firewall Analyzer

![Build](https://github.com/moshekaplan/palo_alto_firewall_analyzer/actions/workflows/test.yml/badge.svg)

Scripts for reviewing Palo Alto Firewall configurations

This repository contains the following main script:

* `pan_policy_validator.py` - Detects Palo Alto Network firewall configuration issues

## Quickstart

The first time you launch the analyzer, it will create a `PAN_CONFIG.cfg` file
in `"~\.pan_policy_analyzer\` and instruct you to edit it.
The second time you launch the analyzer it will detect that "API_KEY.txt" is not present,
and will prompt you for credentials and save the retrieved API key to "API_KEY.txt"

Run a single validator on a single device group:
`pan_policy_validator.py --device-group my_device_group --validator UnusedServices`

Run a single validator on all device groups:
`pan_policy_validator.py --all --validator UnusedServices`

Run all non-API validators on all device groups:
`pan_policy_validator.py --all --no-api`

Run all validators on all device groups (this may take a long time):
`pan_policy_validator.py --all`

## Known Issues

The validators for checking zones (ExtaZones, MissingZones, and ExtraRules) all
require looking up the zones for address objects on the firewall. This requires many API
requests and can take a very long time. Given that PA recommends limiting the number of
concurrent API calls to five, and that's shared among the web UI, these calls are not
parallelized. If you don't need those validators, run with `--no-api` to skip them.

## License ##

This project is in the worldwide [public domain](LICENSE).

This project is in the public domain within the United States, and
copyright and related rights in the work worldwide are waived through
the [CC0 1.0 Universal public domain
dedication](https://creativecommons.org/publicdomain/zero/1.0/).

All contributions to this project will be released under the CC0
dedication. By submitting a pull request, you are agreeing to comply
with this waiver of copyright interest.
