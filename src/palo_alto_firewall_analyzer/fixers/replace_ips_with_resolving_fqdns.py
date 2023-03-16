import logging

from palo_alto_firewall_analyzer.core import register_policy_fixer, get_policy_validators, xml_object_to_dict
from palo_alto_firewall_analyzer import pan_api

logger = logging.getLogger(__name__)

@register_policy_fixer("FixIPWithResolvingFQDN", "Replace IPs with FQDNs that resolve to them")
def fix_bad_log_setting(profilepackage):
    panorama = profilepackage.settings.get("Panorama")
    api_key = profilepackage.api_key
    pan_config = profilepackage.pan_config
    version = pan_config.get_major_version()

    _, _, validator = get_policy_validators()['IPWithResolvingFQDN']
    problems = validator(profilepackage)

    for problem in problems:
        object_type = problem.entry_type
        device_group = problem.device_group
        address_entry, fqdn = problem.data
        updated_object = xml_object_to_dict(address_entry)['entry']
        logger.debug(f"Updating {device_group} Address {address_entry.get('name')} from {updated_object['ip-netmask']} to {fqdn}")
        del updated_object['ip-netmask']
        updated_object['fqdn'] = fqdn
        pan_api.update_devicegroup_object(panorama, version, api_key, updated_object, object_type, device_group)

    return problems
