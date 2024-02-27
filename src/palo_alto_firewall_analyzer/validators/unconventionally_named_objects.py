import logging

from palo_alto_firewall_analyzer.core import BadEntry, register_policy_validator
from palo_alto_firewall_analyzer.core import xml_object_to_dict
from palo_alto_firewall_analyzer.scripts.pan_details import parsed_details

logger = logging.getLogger(__name__)

@register_policy_validator("UnconventionallyNamedServices", "Service objects that don't match the configured naming convention")
def find_unconventional_services(profilepackage):
    device_groups = profilepackage.device_groups
    pan_config = profilepackage.pan_config

    count_checks = 0

    service_name_format = profilepackage.settings.get('service name format')
    if not service_name_format:
        return [], count_checks

    badentries = []    

    logger.info("*"*80)
    logger.info("Checking for misleading Service objects")

    PROTOCOL_TYPES = ('tcp', 'udp')
    for i, device_group in enumerate(device_groups):
        logger.info(f"({i+1}/{len(device_groups)}) Checking {device_group}'s Service objects")
        for service_entry in pan_config.get_devicegroup_object('Services', device_group):
            count_checks += 1
            # For simplicity, convert the XML object to a dict:
            service_dict = xml_object_to_dict(service_entry)
            service_name = service_dict['entry']['@name']
            for protocol_type in PROTOCOL_TYPES:
                if protocol_type in service_dict['entry']['protocol'].keys():
                    entry_protocol = protocol_type
                    break
            else:
                # This should not be possible!
                continue
            # Values retrieved are <transport>, <source-port>, <port>, <override>
            service_fields = {}
            service_fields['transport'] = protocol_type
            service_fields['source_port'] = service_dict['entry']['protocol'][entry_protocol].get('source-port', '')
            service_fields['port'] = service_dict['entry']['protocol'][entry_protocol].get('port', '')
            override = service_dict['entry']['protocol'][entry_protocol].get('override')
            if override:
                service_fields['override'] = tuple(override.keys())[0]
            else:
                service_fields['override'] = ''

            calculated_name = service_name_format.format(**service_fields)

            if service_name != calculated_name:
                text = f"Device Group {device_group}'s Service {service_name} should instead be named {calculated_name}"
                detail = {
                    "device_group": device_group,
                    "entry_type": 'Services',
                    "extra": f"Service: {service_name}, calculated_name: {calculated_name}"
                }
                badentries.append(BadEntry(data=[service_entry, calculated_name], text=text, device_group=device_group, entry_type='Services',Detail=parsed_details(detail)))
    return badentries, count_checks


@register_policy_validator("UnconventionallyNamedAddresses", "Address objects that don't match the configured naming convention")
def find_unconventional_addresses(profilepackage):
    device_groups = profilepackage.device_groups
    pan_config = profilepackage.pan_config

    count_checks = 0
    
    fqdn_name_format = profilepackage.settings.get('fqdn name format')
    range_name_format = profilepackage.settings.get('range name format')
    wildcard_name_format = profilepackage.settings.get('wildcard name format')
    host_name_format = profilepackage.settings.get('host name format')
    net_name_format = profilepackage.settings.get('net name format')
    colon_replacement = profilepackage.settings.get('ipv6 colon replacement char')
    if not fqdn_name_format or not host_name_format or not net_name_format or not range_name_format or not wildcard_name_format:
        return [],count_checks

    badentries = []

    logger.info("*"*80)
    logger.info("Checking for misleading Address objects")

    ADDRESS_TYPES = ('fqdn', 'ip-netmask', 'ip-range', 'ip-wildcard')
    for i, device_group in enumerate(device_groups):
        logger.info(f"({i+1}/{len(device_groups)}) Checking {device_group}'s Address objects")
        for address_entry in pan_config.get_devicegroup_object('Addresses', device_group):
            count_checks+=1
            # For simplicity, convert the XML object to a dict:
            address_dict = xml_object_to_dict(address_entry)
            address_name = address_dict['entry']['@name']

            for address_t in ADDRESS_TYPES:
                if address_t in address_dict['entry'].keys():
                    address_type = address_t
                    break
            else:
                # This should not be possible!
                continue

            address_fields = {}
            if address_type == 'fqdn':
                address_fields['fqdn'] = address_dict['entry']['fqdn']
                calculated_name = fqdn_name_format.format(**address_fields)
            elif address_type == 'ip-range':
                address_fields['range'] = address_dict['entry']['ip-range']
                calculated_name = range_name_format.format(**address_fields)
            elif address_type == 'ip-wildcard':
                address_fields['mask'] = address_dict['entry']['ip-wildcard']
                calculated_name = wildcard_name_format.format(**address_fields)
            elif address_type == 'ip-netmask':
                address_fields['host'] = address_dict['entry']['ip-netmask'].split('/', 1)[0]
                if colon_replacement and ':' in address_fields['host']:
                    address_fields['host'] = address_fields['host'].replace(':', colon_replacement)
                if '/' in address_dict['entry']['ip-netmask']:
                    address_fields['network'] = address_dict['entry']['ip-netmask'].split('/', 1)[1]
                else:
                    address_fields['network'] = ''

                # We'll use the host name pattern for /32's or entries without a netmask:
                is_host = '/' not in address_dict['entry']['ip-netmask'] or ('.' in address_dict['entry']['ip-netmask'] and '/32' in address_dict['entry']['ip-netmask']) or (':' in address_dict['entry']['ip-netmask'] and '/128' in address_dict['entry']['ip-netmask'])
                if is_host:
                    calculated_name = host_name_format.format(**address_fields)
                else:
                    calculated_name = net_name_format.format(**address_fields)

            # PA supports a max char length of 63:
            calculated_name = calculated_name[:63]
            if address_name != calculated_name:
                text = f"Device Group {device_group}'s Address {address_name} should instead be named {calculated_name}"
                detail = {
                    "device_group": device_group,
                    "entry_type": 'Addresses',
                    "extra": f"Address: {address_name}, calculated_name: {calculated_name}"
                }
                badentries.append(BadEntry(data=[address_entry, calculated_name], text=text, device_group=device_group, entry_type='Addresses',Detail=parsed_details(detail)))
    return badentries,count_checks
