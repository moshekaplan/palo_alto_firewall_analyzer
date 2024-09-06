import logging
import re

from palo_alto_firewall_analyzer.core import BadEntry, register_policy_validator
from palo_alto_firewall_analyzer.scripts.pan_details import parsed_details

logger = logging.getLogger(__name__)

@register_policy_validator("FQDNContainsIP", "Address contains an FQDN that is actually an IP address")
def fqdn_contains_ip(profilepackage):
    device_groups = profilepackage.device_groups
    pan_config = profilepackage.pan_config

    IP_REGEX = r"^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])$"
    badentries = []
    count_checks=0
    logger.info("*" * 80)

    for i, device_group in enumerate(device_groups):
        logger.info(f"({i + 1}/{len(device_groups)}) Checking {device_group}'s Addresses")
        for entry in pan_config.get_devicegroup_object('Addresses', device_group):
            entry_name = entry.get('name')            
            loc = entry.get('@loc')            
            for fqdn_node in entry.findall('fqdn'):
                ip_in_fqdn = re.search(IP_REGEX, fqdn_node.text)
                if ip_in_fqdn is not None:
                    text = f"Device Group {device_group}'s address '{entry_name}' uses the following FQDN which appears to be an IP: '{fqdn_node.text}'"
                    detail={
                        "device_group":device_group,
                        "entry_name":entry_name,
                        "fqdn":fqdn_node.text,                                                
                        "entry_type":'Addresses',
                        "loc":loc
                    }
                    badentries.append(
                        BadEntry(data=entry, text=text, device_group=device_group, entry_type='Addresses',Detail=parsed_details(detail)))
                count_checks+=1
    return badentries,count_checks
