from palo_alto_firewall_analyzer.core import register_policy_fixer, get_policy_validators, xml_object_to_dict
from palo_alto_firewall_analyzer import pan_api

@register_policy_fixer("FixUnqualifiedFQDN", "Replace hostnames with FQDNs")
def fix_bad_log_setting(profilepackage):
    panorama = profilepackage.settings.get("Panorama")
    api_key = profilepackage.api_key
    pan_config = profilepackage.pan_config
    version = pan_config.get_major_version()

    _, _, validator = get_policy_validators()['UnqualifiedFQDN']
    problems = validator(profilepackage)

    for problem in problems:
        entry = xml_object_to_dict(problem.data[0])['entry']
        object_type = problem.entry_type
        device_group = problem.device_group
        entry['fqdn'] = problem.data[1]
        pan_api.update_devicegroup_object(panorama, version, api_key, entry, object_type, device_group)

    return problems
