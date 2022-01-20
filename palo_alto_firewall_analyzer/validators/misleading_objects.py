from palo_alto_firewall_analyzer.core import BadEntry, register_policy_validator
from palo_alto_firewall_analyzer.core import xml_object_to_dict

import re

@register_policy_validator("MisleadingAddresses", "Address objects that have a misleading name")
def find_misleading_addresses(profilepackage):
    device_groups = profilepackage.device_groups
    devicegroup_objects = profilepackage.devicegroup_objects
    pan_config = profilepackage.pan_config

    # NOTE: IP Wildcards not supported yet
    ADDRESS_TYPES = ['ip-netmask', 'ip-range', 'fqdn']
    IP_REGEX = r"((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])"
    badentries = []

    print ("*"*80)
    print ("Checking for misleading Address objects")

    for i, device_group in enumerate(device_groups):
        print (f"({i+1}/{len(device_groups)}) Checking {device_group}'s address objects")
        for address_entry in devicegroup_objects[device_group]['Addresses']:
            # For simplicity, convert the XML object to a dict:
            address_dict = xml_object_to_dict(address_entry)
            entry_name = address_dict['entry']['@name']
            for address_type in ADDRESS_TYPES:
                if address_type in address_dict['entry'].keys():
                    entry_type = address_type
                    break
            else:
                # Wildcards are unsupported, and so skipped
                continue

            entry_value = address_dict['entry'][entry_type]

            # The exact strategy will depend on the content type
            # For FQDNs, the domain should be present in the name
            if entry_type == 'fqdn':
                if entry_value.lower().split('.', 1)[0] not in entry_name.lower():
                    text = f"Device Group {device_group}'s Address {entry_name} has a misleading value of {entry_value}, because the FQDN's domain is not present in the name"
                    badentries.append(BadEntry(data=address_entry, text=text, device_group=device_group, entry_type='Addresses'))
            # For IPs, the IP should be present in the name, if the name 'looks' like it contains an IP (based on regex):
            if entry_type == 'ip-netmask':
                # This can optionally include a '/'
                ip_address = entry_value.split('/', 1)[0]
                if ip_address not in entry_name and re.search(IP_REGEX, entry_name) is not None:
                    text = f"Device Group {device_group}'s Address {entry_name} has a misleading value of {entry_value}, because the name appears to contain an IP address, but the IP address is not in the name"
                    badentries.append(BadEntry(data=address_entry, text=text, device_group=device_group, entry_type='Addresses'))
            if entry_type == 'ip-range':
                # This can optionally include a '-'
                ip_address = entry_value.split('-', 1)[0]
                if ip_address not in entry_name and re.search(IP_REGEX, entry_name) is not None:
                    text = f"Device Group {device_group}'s Address {entry_name} has a misleading value of {entry_value}, because the name appears to contain an IP address, but the IP address is not in the name"
                    badentries.append(BadEntry(data=address_entry, text=text, device_group=device_group, entry_type='Addresses'))
    return badentries
