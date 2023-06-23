import logging
import re

from palo_alto_firewall_analyzer.core import BadEntry, register_policy_validator
from palo_alto_firewall_analyzer.core import xml_object_to_dict

logger = logging.getLogger(__name__)

@register_policy_validator("MisleadingAddresses", "Address objects that have a misleading name")
def find_misleading_addresses(profilepackage):
    device_groups = profilepackage.device_groups
    devicegroup_objects = profilepackage.devicegroup_objects

    # NOTE: IP Wildcards not supported yet
    ADDRESS_TYPES = ('ip-netmask', 'ip-range', 'fqdn')
    IP_REGEX = r"((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])"
    badentries = []

    logger.info ("*"*80)
    logger.info ("Checking for misleading Address objects")

    for i, device_group in enumerate(device_groups):
        logger.info (f"({i+1}/{len(device_groups)}) Checking {device_group}'s Address objects")
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
                # FQDNs can be up to 255 characters, but names are limited to 63 characters
                # As such, skip FQDNs that are 63 or more characters, to avoid false positives
                if len(entry_value) < 63 and entry_value.lower().split('.', 1)[0] not in entry_name.lower():
                    text = f"Device Group {device_group}'s Address {entry_name} has a misleading value of {entry_value}, because the FQDN's domain is not present in the name"
                    badentries.append(BadEntry(data=address_entry, text=text, device_group=device_group, entry_type='Addresses'))
            # For IPs, the IP should be present in the name, if the name 'looks' like it contains an IP (based on regex):
            elif entry_type == 'ip-netmask':
                # This can optionally include a '/'
                ip_address = entry_value.split('/', 1)[0]
                if ip_address not in entry_name and re.search(IP_REGEX, entry_name) is not None:
                    text = f"Device Group {device_group}'s Address {entry_name} appears to contain an IP address in the name, but has a different value of {entry_value}"
                    badentries.append(BadEntry(data=address_entry, text=text, device_group=device_group, entry_type='Addresses'))
            elif entry_type == 'ip-range':
                # This can optionally include a '-'
                ip_address = entry_value.split('-', 1)[0]
                if ip_address not in entry_name and re.search(IP_REGEX, entry_name) is not None:
                    text = f"Device Group {device_group}'s Address {entry_name} appears to contain an IP address in the name, but has a different value of {entry_value}"
                    badentries.append(BadEntry(data=address_entry, text=text, device_group=device_group, entry_type='Addresses'))
    return badentries


@register_policy_validator("MisleadingServices", "Service objects that have a misleading name")
def find_misleading_services(profilepackage):
    device_groups = profilepackage.device_groups
    devicegroup_objects = profilepackage.devicegroup_objects

    PROTOCOL_TYPES = ('tcp', 'udp')

    badentries = []

    logger.info ("*"*80)
    logger.info ("Checking for misleading Service objects")

    for i, device_group in enumerate(device_groups):
        logger.info (f"({i+1}/{len(device_groups)}) Checking {device_group}'s Service objects")
        for service_entry in devicegroup_objects[device_group]['Services']:
            # For simplicity, convert the XML object to a dict:
            service_dict = xml_object_to_dict(service_entry)
            entry_name = service_dict['entry']['@name']
            for protocol_type in PROTOCOL_TYPES:
                if protocol_type in service_dict['entry']['protocol'].keys():
                    entry_protocol = protocol_type
                    break
            else:
                # This should not be possible!
                continue
            entry_port = service_dict['entry']['protocol'][entry_protocol]['port']
            contains_protocol = 'tcp' in entry_name.lower() or 'udp' in entry_name.lower()
            contains_port = re.search(r'\d{3,}', entry_name) is not None
            protocol_correct = entry_protocol in entry_name.lower()
            port_correct = entry_port.split('-',1)[0] in entry_name

            if contains_protocol or contains_port:
                if contains_protocol and not protocol_correct and contains_port and not port_correct:
                    text = f"Device Group {device_group}'s Service {entry_name} uses protocol {entry_protocol} and port {entry_port}"
                    badentries.append(BadEntry(data=service_entry, text=text, device_group=device_group, entry_type='Services'))
                elif contains_protocol and not protocol_correct:
                    text = f"Device Group {device_group}'s Service {entry_name} uses protocol {entry_protocol}"
                    badentries.append(BadEntry(data=service_entry, text=text, device_group=device_group, entry_type='Services'))
                elif contains_port and not port_correct:
                    text = f"Device Group {device_group}'s Service {entry_name} uses port {entry_port}"
                    badentries.append(BadEntry(data=service_entry, text=text, device_group=device_group, entry_type='Services'))
    return badentries
