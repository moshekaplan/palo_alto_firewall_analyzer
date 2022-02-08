from palo_alto_firewall_analyzer.core import BadEntry, register_policy_validator

def find_unused_security_profile_groups(profilepackage, object_type, object_friendly_type):
    device_groups = profilepackage.device_groups
    pan_config = profilepackage.pan_config
    devicegroup_objects = profilepackage.devicegroup_objects
    rule_limit_enabled = profilepackage.rule_limit_enabled

    if rule_limit_enabled:
        return []

    badentries = []

    print("*" * 80)
    print(f"Checking for unused {object_friendly_type} objects")

    for i, device_group in enumerate(device_groups):
        print(f"({i + 1}/{len(device_groups)}) Checking {device_group}'s {object_friendly_type} objects")
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
        for unused_group in unused_groups:
            text = f"Device Group {device_group}'s {object_friendly_type} {unused_group} is not used by any Security Policies"
            badentries.append(
                BadEntry(data=[groups[unused_group]], text=text, device_group=device_group, entry_type=object_type))
    return badentries


@register_policy_validator("UnusedSecurityProfileGroups", "Security Profile Group objects that aren't in use")
def find_unused_services(profilepackage):
    object_type = "SecurityProfileGroups"
    object_friendly_type = "Security Profile Group"
    badentries = find_unused_security_profile_groups(profilepackage, object_type, object_friendly_type)
    return badentries
