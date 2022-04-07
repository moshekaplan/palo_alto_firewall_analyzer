from palo_alto_firewall_analyzer.core import BadEntry, cached_dns_lookup, register_policy_validator, get_policy_validators

import re

@register_policy_validator("FQDNContainsIP", "Address contains an FQDN that is actually an IP address")
def find_badhostname(profilepackage):
    device_groups = profilepackage.device_groups
    pan_config = profilepackage.pan_config

    IP_REGEX = r"^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])$"
    badentries = []

    print("*" * 80)

    for i, device_group in enumerate(device_groups):
        print(f"({i + 1}/{len(device_groups)}) Checking {device_group}'s Addresses")
        for entry in pan_config.get_devicegroup_object('Addresses', device_group):
            entry_name = entry.get('name')
            for fqdn_node in entry.findall('fqdn'):
                ip_in_fqdn = re.search(IP_REGEX, fqdn_node.text)
                if ip_in_fqdn is not None:
                    text = f"Device Group {device_group}'s address '{entry_name}' uses the following FQDN which appears to be an IP: '{fqdn_node.text}'"
                    badentries.append(
                        BadEntry(data=entry, text=text, device_group=device_group, entry_type='Addresses'))
    return badentries
