import logging

from palo_alto_firewall_analyzer.core import register_policy_validator, BadEntry
from palo_alto_firewall_analyzer.scripts.pan_details  import parsed_details

logger = logging.getLogger(__name__)

@register_policy_validator("BadGroupProfile", "Rule uses an incorrect group profile")
def find_bad_group_profile_setting(profilepackage):
    device_groups = profilepackage.device_groups
    devicegroup_exclusive_objects = profilepackage.devicegroup_exclusive_objects    
    count_checks=0
    
    if not profilepackage.settings.get('Allowed Group Profiles'):
        logger.debug("Allowed Group Profiles are not set; skipping")
        return [],count_checks

    allowed_group_profiles = profilepackage.settings.get('Allowed Group Profiles').split(',')

    badentries = []
    
    logger.info("*"*80)
    logger.info("Checking for incorrect group profile")
    
    for i, device_group in enumerate(device_groups):
        for ruletype in ('SecurityPreRules', 'SecurityPostRules'):
            rules = devicegroup_exclusive_objects[device_group][ruletype]
            logger.warning(f"({i+1}/{len(device_groups)}) Checking {device_group}'s {ruletype}")

            for entry in rules:
                # Disabled rules can be ignored
                if entry.find("./disabled") is not None and entry.find("./disabled").text == "yes":
                    continue

                rule_name = entry.get('name')
                group_profile_setting_node = entry.find("./profile-setting/group/member")
                if group_profile_setting_node is not None:
                    group_profile_setting = group_profile_setting_node.text
                else:
                    group_profile_setting = ""

                if group_profile_setting not in allowed_group_profiles:                    
                    text = f"Device Group {device_group}'s {ruletype} '{rule_name}' doesn't use an approved group " \
                           f"profile '{allowed_group_profiles}', instead it uses '{group_profile_setting}' "
                    logger.debug(text)
                    detail={
                            "entry_type":ruletype,
                            "device_group":device_group,
                            "rule_type":ruletype,
                            "rule_name":rule_name,
                            "allowed_group_profiles":allowed_group_profiles,
                            "group_profile_setting":group_profile_setting
                            }
                    badentries.append( BadEntry(data=entry, text=text, device_group=device_group, entry_type=ruletype, Detail=parsed_details(detail)) )
                count_checks+=1
    print(count_checks)
    return badentries, count_checks