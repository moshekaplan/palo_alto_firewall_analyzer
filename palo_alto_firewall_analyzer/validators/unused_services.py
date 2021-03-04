from palo_alto_firewall_analyzer.core import BadEntry, register_policy_validator


@register_policy_validator("UnusedServices", "Services objects that aren't in use")
def find_unused_services(profilepackage):
    device_groups = profilepackage.device_groups
    devicegroup_objects = profilepackage.devicegroup_objects
    pan_config = profilepackage.pan_config

    rule_limit_enabled = profilepackage.rule_limit_enabled

    if rule_limit_enabled:
        return []

    badentries = []

    print("*" * 80)
    print("Checking for unused Services objects")

    for i, device_group in enumerate(device_groups):
        print(f"({i + 1}/{len(device_groups)}) Checking {device_group}'s Services objects")
        services = {entry.get('name'): entry for entry in devicegroup_objects[device_group]['Services']}

        # A Services object can be used by any child device group's Services Group or Policy. Need to check all of them.
        services_in_use = set()
        for child_dg in devicegroup_objects[device_group]['all_child_device_groups']:
            # First check all child Services Groups
            for servicegroup in devicegroup_objects[child_dg]['ServiceGroups']:
                for member_element in servicegroup.findall('./members/member'):
                    services_in_use.add(member_element.text)
            # Then check all of the policies
            for policytype in pan_config.SUPPORTED_POLICY_TYPES:
                for policy_entry in devicegroup_objects[child_dg][policytype]:
                    if policytype in ("NATPreRules", "NATPostRules"):
                        for service_element in policy_entry.findall('./service'):
                            services_in_use.add(service_element.text)
                    else:
                        for service_child_element in policy_entry.findall('./service/'):
                            services_in_use.add(service_child_element.text)

        unused_services = sorted(set(services.keys()) - services_in_use)
        for unused_service in unused_services:
            text = f"Device Group {device_group}'s Service {unused_service} is not in use for any Policies or Service Groups"
            badentries.append(
                BadEntry(data=[services[unused_service]], text=text, device_group=device_group, entry_type='Services'))

    return badentries
