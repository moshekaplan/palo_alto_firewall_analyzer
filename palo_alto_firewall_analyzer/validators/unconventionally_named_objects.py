from palo_alto_firewall_analyzer.core import BadEntry, register_policy_validator
from palo_alto_firewall_analyzer.core import xml_object_to_dict


@register_policy_validator("UnconventionallyNamedServices", "Service objects that don't match the configured naming convention")
def find_unconventional_services(profilepackage):
    device_groups = profilepackage.device_groups
    pan_config = profilepackage.pan_config

    service_name_format = profilepackage.settings.get('service name format')
    if not service_name_format:
        return []

    badentries = []

    print("*"*80)
    print("Checking for misleading Service objects")

    PROTOCOL_TYPES = ('tcp', 'udp')
    for i, device_group in enumerate(device_groups):
        print(f"({i+1}/{len(device_groups)}) Checking {device_group}'s Service objects")
        for service_entry in pan_config.get_devicegroup_object('Services', device_group):
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
                badentries.append(BadEntry(data=[service_entry, calculated_name], text=text, device_group=device_group, entry_type='Services'))
    return badentries
