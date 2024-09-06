# Palo Alto Firewall Analyzer

![Build](https://github.com/moshekaplan/palo_alto_firewall_analyzer/actions/workflows/test.yml/badge.svg)![Test coverage](https://img.shields.io/endpoint?url=https://gist.githubusercontent.com/moshekaplan/1165ad4d7c2e8827ec6573b8bee2b7d9/raw/fde8d53ea40cfed2cdd758f022503b02a62cf55a/covbadge.json)

Python3 scripts for reviewing and fixing Palo Alto Firewall configurations

This repository contains the script `pan_analyzer`, which can detects and fix Palo Alto Network firewall configuration issues, as well as several other helper scripts.

The validators are designed to have as few false positives as possible. If there is a false positive, please [report an issue](https://github.com/moshekaplan/palo_alto_firewall_analyzer/issues/new)!

## pan_analyzer Quickstart

1. Install the package with `pip install pan_analyzer`
2. Run all validators on an XML configuration file downloaded with Panorama -> Setup -> Operations -> "Export Panorama configuration version":
`pan_analyzer --xml 12345.xml`

## Using pan_analyzer

The first time you launch pan_analyzer, it will create a `PAN_CONFIG.cfg` file
in `"~\.pan_policy_analyzer\` and instruct you to edit it.
The second time you launch the analyzer it will detect that "API_KEY.txt" is not present,
and will prompt you for credentials and save the retrieved API key to "API_KEY.txt"

* Run all validators on all device groups:
`pan_analyzer`

* Run a single validator on all device groups:
`pan_analyzer --validator UnusedServices`

* Run a single validator on a single device group:
`pan_analyzer --device-group my_device_group --validator UnusedServices`

* Run all validators on an XML configuration file downloaded with "Export Panorama configuration version":
`pan_analyzer --xml 12345.xml`

* Run all validators on an XML configuration file downloaded with "Export Panorama configuration version" and choose type output file (formats support txt (text) and json (json)):

`pan_analyzer --xml 12345.xml --output-format text`
`pan_analyzer --xml 12345.xml --output-format json`

If you're not sure where to start, I recommend downloading an XML file from:
`Panorama -> Setup -> Operations -> Export Panorama configuration version` and running: `pan_analyzer.py --xml 12345.xml`

## Common Workflows
There are a few common workflows to clean the firewall configuration:

### Consolidate Service Objects
Consolidate Service objects so there is only one object for each Service:
* Delete unused Service objects: `python pan_analyzer --fixer DeleteUnusedServices`
* Check if any Service objects have misleading names: `python pan_analyzer --validator MisleadingServices`
* Consolidate service objects in use: `python pan_analyzer --fixer ConsolidateServices`
* Delete the now-unused Service objects: `python pan_analyzer --fixer DeleteUnusedServices`
* Define a convention in the config file, then rename to fit the naming convention: `python pan_analyzer --fixer RenameUnconventionallyNamedServices`

### Consolidate Address Objects
Consolidate Address objects so there is only one object for each target:
* Delete unused Address objects: `python pan_analyzer --fixer DeleteUnusedAddresses`
* Delete Address objects with FQDNs that don't resolve: `python pan_analyzer --validator BadHostname`
* Check if any Address objects have IPs in FQDNs: `python pan_analyzer --validator FQDNContainsIP`
* Check if any Address objects have misleading names: `python pan_analyzer --validator MisleadingAddresses`
* Replace Address objects using IPs with FQDNs: `python pan_analyzer --fixer FixIPWithResolvingFQDN`
* Consolidate Address objects in use: `python pan_analyzer --fixer ConsolidateAddresses`
* Delete the now-unused Address objects: `python pan_analyzer --fixer DeleteUnusedAddresses`
* Make all FQDN objects use FQDNs: `python pan_analyzer --fixer FixUnqualifiedFQDN`
* Define a convention in the config file, then rename objects to fit a naming convention: `python pan_analyzer --fixer RenameUnconventionallyNamedAddresses`


## Known Issues

The validators for checking zones (ExtaZones, MissingZones, and ExtraRules) all
require looking up the zones for address objects on the firewall. This requires many API
requests and can take a very long time. Given that PA recommends limiting the number of
concurrent API calls to five, and that's shared among the web UI, these calls are not
parallelized. Because of these concerns, the default configuration skips those validators.

## Other scripts
In addition to **pan_analyzer**, several other scripts are included in this package:
* **pan_categorization_lookup** - Looks up categorization for either a single URL or a file with a list of URLs
* **pan_disable_rules** - Takes a textfile with a list of security rules and disables them (useful for disabling rules found with PolicyOptimizer)
* **pan_dump_active_sessions** - Dumps all active sessions from all firewalls
* **pan_run_command** - Runs a single command on a single firewall
* **pan_zone_lookup** - Looks up Zone for a single IP on all firewalls

## License ##

This project is in the worldwide [public domain](LICENSE).

This project is in the public domain within the United States, and
copyright and related rights in the work worldwide are waived through
the [CC0 1.0 Universal public domain
dedication](https://creativecommons.org/publicdomain/zero/1.0/).

All contributions to this project will be released under the CC0
dedication. By submitting a pull request, you are agreeing to comply
with this waiver of copyright interest.
