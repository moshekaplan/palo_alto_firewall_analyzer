import collections

from palo_alto_firewall_analyzer.core import BadEntry, register_policy_validator


def get_underlying_services(servicegroup_name, all_servicegroups_to_members):
    """Given an AddressGroup, retrieves a set of all address and addressgroup objects effectively contained within"""
    underlying_members = []
    for member in all_servicegroups_to_members[servicegroup_name]:
        if member in all_servicegroups_to_members:
            # Include both the Address Group itself and its contained members
            underlying_members += [member]
            underlying_members += get_underlying_services(member, all_servicegroups_to_members)
        else:
            underlying_members += [member]
    return set(underlying_members)


def build_servicegroup_members(pan_config, device_group):
    """Creates a mapping of AddressGroup objects to the underlying Address objects"""
    all_servicegroups_to_members = {}
    for service_group_entry in pan_config.get_devicegroup_all_objects('ServiceGroups', device_group):
        name = service_group_entry.get('name')
        members = [member.text for member in service_group_entry.findall('./members/member')]
        breakpoint()
        all_servicegroups_to_members[name] = members

    servicegroup_to_effective_members = {}
    for servicegroup_name in all_servicegroups_to_members:
        servicegroup_to_effective_members[servicegroup_name] = get_underlying_services(servicegroup_name, all_servicegroups_to_members)
    return servicegroup_to_effective_members


@register_policy_validator("RedundantRuleServices", "Detects rules with redundant Service entries")
def find_redundant_members(profilepackage):
    device_groups = profilepackage.device_groups
    pan_config = profilepackage.pan_config

    badentries = []

    print("*" * 80)
    print("Checking for redundant rule services")

    for i, device_group in enumerate(device_groups):
        print(f"Checking Device group {device_group}")
        addressgroups_to_underlying_addresses = build_servicegroup_members(pan_config, device_group)

        for ruletype in ('SecurityPreRules', 'SecurityPostRules'):
            for rule_entry in pan_config.get_devicegroup_policy(ruletype, device_group):
                # Skip disabled rules:
                if rule_entry.find("./disabled") is not None and rule_entry.find("./disabled").text == "yes":
                    continue
                members_to_remove = collections.defaultdict(list)
                for direction in ('source', 'destination'):
                    # Split the address-like members into addresses and address_groups
                    address_like_members = [elem.text for elem in rule_entry.findall(f'./{direction}/member')]
                    addressgroups_used = []
                    for address_like_member in address_like_members:
                        if address_like_member in addressgroups_to_underlying_addresses:
                            addressgroups_used += [address_like_member]
                    # See which address objects are contained within the rule's other addressgroup objects:
                    for address_like_member in address_like_members:
                        for ag in addressgroups_used:
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
