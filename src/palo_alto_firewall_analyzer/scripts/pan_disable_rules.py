#!/usr/bin/env python
# Script for disabling a list of rules from a given device group
# This is intended to aid cleaning up unused rules
# discovered with Policy Optimizer

import argparse
import os


from palo_alto_firewall_analyzer import pan_api
from palo_alto_firewall_analyzer.core import xml_object_to_dict
from palo_alto_firewall_analyzer.pan_config import PanConfig
from palo_alto_firewall_analyzer.pan_helpers import load_API_key


DEFAULT_CONFIG_DIR = os.path.expanduser("~\\.pan_policy_analyzer\\")
DEFAULT_API_KEYFILE = DEFAULT_CONFIG_DIR + "API_KEY.txt"


def main():
    parser = argparse.ArgumentParser(description="Disable a list of security rules")
    parser.add_argument("panorama", nargs=1, help="Panorama to run on")
    parser.add_argument("device-group", nargs=1, help="Device Group to disable rules from")
    parser.add_argument("policy_type", nargs=1, help="Policy type", choices=['SecurityPreRules', 'SecurityPostRules'])
    parser.add_argument("infile", nargs=1, help="Input file with list of rules to disable")
    parser.add_argument("--api", help=f"File with API Key (default is {DEFAULT_API_KEYFILE})", default=DEFAULT_API_KEYFILE)

    parsed_args = parser.parse_args()
    api_key = load_API_key(parsed_args.api)

    with open(parsed_args.infile[0]) as fh:
        rules_to_disable = set(fh.read().splitlines())

    panorama = parsed_args.panorama[0]
    device_group = vars(parsed_args)['device-group'][0]
    policy_type = parsed_args.policy_type[0]

    xml_config = pan_api.export_configuration2(panorama, api_key)
    pan_config = PanConfig(xml_config)

    version = pan_config.get_major_version()

    for policy_entry in pan_config.get_devicegroup_policy(policy_type, device_group):
        rule_name = policy_entry.get('name')
        if rule_name in rules_to_disable:
            disabled = (policy_entry.find('disabled') is not None and policy_entry.find('disabled').text == 'yes')
            if disabled:
                print(f"Policy {rule_name} was already disabled, no action needed!")
            else:
                policy_dict = xml_object_to_dict(policy_entry)['entry']
                policy_dict['disabled'] = 'yes'
                print(f"Disabling {device_group}'s {policy_type} {rule_name}")
                pan_api.update_devicegroup_policy(panorama, version, api_key, policy_dict, policy_type, device_group)


if __name__ == '__main__':
    main()
