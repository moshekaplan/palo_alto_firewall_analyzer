import logging

from palo_alto_firewall_analyzer.core import BadEntry, register_policy_validator
from palo_alto_firewall_analyzer.scripts.pan_details import parsed_details

logger = logging.getLogger(__name__)

def find_unused_security_profile_groups(profilepackage, object_type, object_friendly_type):
    device_groups = profilepackage.device_groups
    pan_config = profilepackage.pan_config
    devicegroup_objects = profilepackage.devicegroup_objects
    rule_limit_enabled = profilepackage.rule_limit_enabled

    count_checks = 0

    if rule_limit_enabled:
        return [], count_checks

    badentries = []

    logger.info("*" * 80)
    logger.info(f"Checking for unused {object_friendly_type} objects")

    for i, device_group in enumerate(device_groups):
        logger.info(f"({i + 1}/{len(device_groups)}) Checking {device_group}'s {object_friendly_type} objects")
        groups = {entry.get('name'): entry for entry in pan_config.get_devicegroup_object(object_type, device_group)}
        if not groups:
            continue
        # A Security Profile Group object can be used by any child device group's Security Policy. Need to check all of them.
        groups_in_use = set()
        for child_dg in devicegroup_objects[device_group]['all_child_device_groups']:
            for policytype in ["SecurityPreRules", "SecurityPostRules"]:
                security_rules = pan_config.get_devicegroup_policy(policytype, child_dg)
                for policy_entry in security_rules:
                    for service_child_element in policy_entry.findall('profile-setting/group/member'):
                        groups_in_use.add(service_child_element.text)

        unused_groups = sorted(set(groups.keys()) - groups_in_use)
        count_checks = len(set(groups.keys()))
        for unused_group in unused_groups:
            text = f"Device Group {device_group}'s {object_friendly_type} {unused_group} is not used by any Security Policies"
            detail={
                "device_group":device_group,
                "entry_type":object_type,
                "entry_name":object_friendly_type,
                "extra":f"object_friendly_type: {object_friendly_type}, Total Groups: {len(set(groups.keys()))}, Groups in Use: {len(groups_in_use)}, unused_group: {unused_group}"
            }
            badentries.append(
                BadEntry(data=[groups[unused_group]], text=text, device_group=device_group, entry_type=object_type,Detail=parsed_details(detail)))
    return badentries,count_checks


@register_policy_validator("UnusedSecurityProfileGroups", "Security Profile Group objects that aren't in use")
def find_unused_services(profilepackage):
    object_type = "SecurityProfileGroups"
    object_friendly_type = "Security Profile Group"    
    badentries,count_checks = find_unused_security_profile_groups(profilepackage, object_type, object_friendly_type)
    return badentries,count_checks
