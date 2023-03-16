import logging

from palo_alto_firewall_analyzer.core import register_policy_fixer, get_policy_validators, xml_object_to_dict
from palo_alto_firewall_analyzer import pan_api

logger = logging.getLogger(__name__)

@register_policy_fixer("FixBadLogSetting", "Fix bad log setting")
def fix_bad_log_setting(profilepackage):
    panorama = profilepackage.settings.get("Panorama")
    api_key = profilepackage.api_key
    pan_config = profilepackage.pan_config
    version = pan_config.get_major_version()

    _, _, validator = get_policy_validators()['BadLogSetting']
    problems = validator(profilepackage)

    for problem in problems:
        entry = xml_object_to_dict(problem.data[0])['entry']
        ruletype = problem.entry_type
        device_group = problem.device_group
        entry["log-setting"] = problem.data[1]
        logger.debug(f"Updating {device_group}'s {ruletype} {problem.data[0].get('name')} log-setting to {entry['log-setting']}")
        pan_api.update_devicegroup_policy(panorama, version, api_key, entry, ruletype, device_group)

    return problems
