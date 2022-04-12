from palo_alto_firewall_analyzer.core import BadEntry, register_policy_validator


def get_underlying_addresses(addressgroup_name, all_addressgroups_to_members):
    """Given an AddressGroup, replaces all menber addressgroup objects with the underlying address objects"""
    underlying_members = []
    for member in all_addressgroups_to_members[addressgroup_name]:
        if member in all_addressgroups_to_members:
            # Include both the Address Group itself and its contained members
            underlying_members += [member]
            underlying_members += get_underlying_addresses(member, all_addressgroups_to_members)
        else:
            underlying_members += [member]
    return set(underlying_members)


def build_addressgroup_members(pan_config, device_group):
    """Creates a mapping of AddressGroup objects to the underlying Address objects"""
    all_addressgroups_to_members = {}
    for address_group_entry in pan_config.get_devicegroup_all_objects('AddressGroups', device_group):
        name = address_group_entry.get('name')
        members = [member.text for member in address_group_entry.findall('./static/member')]
        all_addressgroups_to_members[name] = members

    addressgroup_to_effective_members = {}
    for addressgroup_name in all_addressgroups_to_members:
        addressgroup_to_effective_members[addressgroup_name] = get_underlying_addresses(addressgroup_name, all_addressgroups_to_members)
    return addressgroup_to_effective_members


@register_policy_validator("RedundantRuleMembers", "Detects rules with redundant entries in the source or destination addresses")
def find_redundant_members(profilepackage):
    device_groups = profilepackage.device_groups
    pan_config = profilepackage.pan_config

    badentries = []

    print("*" * 80)
    print("Checking for redundant rule members")

    for i, device_group in enumerate(device_groups):
        print(f"Checking Device group {device_group}")
        # Build the list of all AddressGroups:
        addressgroups_to_underlying_addresses = build_addressgroup_members(pan_config, device_group)

        for ruletype in ('SecurityPreRules', 'SecurityPostRules'):
            for rule_entry in pan_config.get_devicegroup_policy(ruletype, device_group):
                # Skip disabled rules:
                if rule_entry.find("./disabled") is not None and rule_entry.find("./disabled").text == "yes":
                    continue
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
                                rule_name = rule_entry.get('name')
                                text = f"Device Group {device_group}'s {ruletype} '{rule_name}' {direction} contains {address_like_member} which is already included with AddressGroup '{ag}'"
                                badentries.append(BadEntry(data=(ruletype, rule_name, direction, address_like_member), text=text, device_group=device_group, entry_type='Address'))
    return badentries
