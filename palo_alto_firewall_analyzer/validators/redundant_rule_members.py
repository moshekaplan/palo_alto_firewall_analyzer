import collections

from palo_alto_firewall_analyzer.core import BadEntry, register_policy_validator


def get_contained_objects(group_name, all_groups_to_members):
    """Given a the name of an AddressGroup or ServiceGroup, retrieves a set of all the names of objects effectively contained within"""
    contained_members = []
    for member in all_groups_to_members[group_name]:
        if member in all_groups_to_members:
            # Include both the Group itself and its contained members
            contained_members += [member]
            contained_members += get_contained_objects(member, all_groups_to_members)
        else:
            contained_members += [member]
    return set(contained_members)


def build_group_member_mapping(pan_config, device_group, object_type, xpath):
    """Creates a mapping of AddressGroup or ServiceGroup objects to the underlying objects"""
    all_groups_to_members = {}
    for group_entry in pan_config.get_devicegroup_all_objects(object_type, device_group):
        name = group_entry.get('name')
        members = [member.text for member in group_entry.findall(xpath)]
        all_groups_to_members[name] = members

    group_to_contained_members = {}
    for group_name in all_groups_to_members:
        group_to_contained_members[group_name] = get_contained_objects(group_name, all_groups_to_members)
    return group_to_contained_members


@register_policy_validator("RedundantRuleAddresses", "Detects rules with redundant entries in the source or destination addresses")
def find_redundant_addresses(profilepackage):
    device_groups = profilepackage.device_groups
    pan_config = profilepackage.pan_config

    badentries = []

    print("*" * 80)
    print("Checking for redundant rule members")

    for i, device_group in enumerate(device_groups):
        print(f"Checking Device group {device_group}")
        # Build the list of all AddressGroups:
        object_type = 'AddressGroups'
        addressgroup_member_xpath = './static/member'
        addressgroups_to_underlying_addresses = build_group_member_mapping(pan_config, device_group, object_type, addressgroup_member_xpath)

        for ruletype in ('SecurityPreRules', 'SecurityPostRules'):
            for rule_entry in pan_config.get_devicegroup_policy(ruletype, device_group):
                # Skip disabled rules:
                if rule_entry.find("./disabled") is not None and rule_entry.find("./disabled").text == "yes":
                    continue
                members_to_remove = collections.defaultdict(list)
                for direction in ('source', 'destination'):
                    # Determine which entries are Address Groups
                    address_like_members = [elem.text for elem in rule_entry.findall(f'./{direction}/member')]
                    addressgroups_in_use = []
                    for address_like_member in address_like_members:
                        if address_like_member in addressgroups_to_underlying_addresses:
                            addressgroups_in_use += [address_like_member]
                    # See which address objects are contained within the rule's other addressgroup objects:
                    for address_like_member in address_like_members:
                        for ag in addressgroups_in_use:
                            if address_like_member in addressgroups_to_underlying_addresses[ag]:
                                members_to_remove[direction] += [(address_like_member, ag)]
                if members_to_remove:
                    rule_name = rule_entry.get('name')
                    text = f"Device Group {device_group}'s {ruletype} '{rule_name}' contains redundant members. "
                    for direction, entries in members_to_remove.items():
                        entries_string = ", ".join([f"'{entry[0]}' is in '{entry[1]}'" for entry in entries])
                        direction_string = f"For {direction}: {entries_string}"
                        text += direction_string
                    badentries.append(BadEntry(data=(ruletype, rule_entry, members_to_remove), text=text, device_group=device_group, entry_type='Address'))
    return badentries


@register_policy_validator("RedundantRuleServices", "Detects rules with redundant Service entries")
def find_redundant_services(profilepackage):
    device_groups = profilepackage.device_groups
    pan_config = profilepackage.pan_config

    badentries = []

    print("*" * 80)
    print("Checking for redundant rule members")

    for i, device_group in enumerate(device_groups):
        print(f"Checking Device group {device_group}")
        # Build the list of all ServiceGroups:
        object_type = 'ServiceGroups'
        service_member_xpath = './members/member'
        servicegroups_to_underlying_services = build_group_member_mapping(pan_config, device_group, object_type, service_member_xpath)

        for ruletype in ('SecurityPreRules', 'SecurityPostRules'):
            for rule_entry in pan_config.get_devicegroup_policy(ruletype, device_group):
                # Skip disabled rules:
                if rule_entry.find("./disabled") is not None and rule_entry.find("./disabled").text == "yes":
                    continue
                members_to_remove = []
                # Determine which entries are Service Groups
                service_members = [elem.text for elem in rule_entry.findall('./service/member')]
                servicegroups_in_use = []
                for service_like_member in service_members:
                    if service_like_member in servicegroups_to_underlying_services:
                        servicegroups_in_use += [service_like_member]
                # See which address objects are contained within the rule's other addressgroup objects:
                for service_like_member in service_members:
                    for sg in servicegroups_in_use:
                        if service_like_member in servicegroups_to_underlying_services[sg]:
                            members_to_remove += [(service_like_member, sg)]

                if members_to_remove:
                    rule_name = rule_entry.get('name')
                    entries_string = ", ".join([f"'{redundant_entry}' is in '{containing_entry}'" for redundant_entry, containing_entry in members_to_remove])
                    text = f"Device Group {device_group}'s {ruletype} '{rule_name}'\'s services list contains redundant members: {entries_string}"
                    badentries.append(BadEntry(data=(ruletype, rule_entry, members_to_remove), text=text, device_group=device_group, entry_type='Address'))
    return badentries
