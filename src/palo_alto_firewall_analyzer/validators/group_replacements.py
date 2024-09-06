import logging

from palo_alto_firewall_analyzer.core import BadEntry, register_policy_validator
from palo_alto_firewall_analyzer.scripts.pan_details import parsed_details

logger = logging.getLogger(__name__)

def get_contained_objects(group_name, all_groups_to_members):
    """Given a the name of an AddressGroup or ServiceGroup, retrieves a set of all the names of objects effectively contained within"""
    contained_members = []
    for member in all_groups_to_members[group_name]:
        if member in all_groups_to_members:
            # do NOT include the Group member itself and its contained members
            # contained_members += [member]
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


@register_policy_validator("AddressesShouldBeGroups", "Detects rules with Addresses that can be replaced with Address Groups")
def find_redundant_addresses(profilepackage):
    device_groups = profilepackage.device_groups
    pan_config = profilepackage.pan_config

    badentries = []
    count_checks=0
    logger.info("*" * 80)
    logger.info("Checking for redundant rule address members")

    for i, device_group in enumerate(device_groups):
        logger.info(f"Checking Device group {device_group}")
        # Build the list of all AddressGroups:
        object_type = 'AddressGroups'
        addressgroup_member_xpath = './static/member'
        addressgroups_to_underlying_addresses = build_group_member_mapping(pan_config, device_group, object_type, addressgroup_member_xpath)
        # Build mapping of entries to group names:
        # Equivalent groups are not an issue -> They can be deduped with a separate validator
        # However, this won't be able to detect nested groups replacements well. That can be a future enhancement.
        members_to_groupnames = {}
        for group_name, members in addressgroups_to_underlying_addresses.items():
            members_to_groupnames[tuple(sorted(members))] = group_name

        for ruletype in ('SecurityPreRules', 'SecurityPostRules'):
            for rule_entry in pan_config.get_devicegroup_policy(ruletype, device_group):
                # Skip disabled rules:
                if rule_entry.find("./disabled") is not None and rule_entry.find("./disabled").text == "yes":
                    continue
                members_to_replace = {}
                for direction in ('source', 'destination'):
                    count_checks+=1
                    # Determine which entries are equivalent to Address Groups
                    address_like_members = tuple(sorted([elem.text for elem in rule_entry.findall(f'./{direction}/member')]))
                    if address_like_members in members_to_groupnames:
                        groupname = members_to_groupnames[address_like_members]
                        members_to_replace[direction] = groupname
                if members_to_replace:
                    rule_name = rule_entry.get('name')
                    text = f"Device Group {device_group}'s {ruletype} '{rule_name}' "
                    direction_strings = []
                    for direction, groupname in members_to_replace.items():
                        direction_string = f"{direction} addresses can be replaced with '{groupname}'"
                        direction_strings += [direction_string]
                    text += " and ".join(direction_strings)
                    detail={
                        "device_group": device_group,
                        "entry_type":'Address',
                        "rule_type":ruletype,
                        "rule_name":rule_name,
                        "extra":f"Direction_string: {direction_strings}"
                    }
                    badentries.append(BadEntry(data=(ruletype, rule_entry, members_to_replace), text=text, device_group=device_group, entry_type='Address',Detail=parsed_details(detail)))
    return badentries,count_checks


@register_policy_validator("ServicesShouldBeGroups", "Detects rules with Services that can be replaced with Service Groups")
def find_redundant_members(profilepackage):
    device_groups = profilepackage.device_groups
    pan_config = profilepackage.pan_config

    count_checks = 0

    badentries = []

    logger.info("*" * 80)
    logger.info("Checking for redundant rule members")

    for i, device_group in enumerate(device_groups):
        logger.info(f"Checking Device group {device_group}")
        # Build the list of all ServiceGroups:
        object_type = 'ServiceGroups'
        service_member_xpath = './members/member'
        servicegroups_to_underlying_services = build_group_member_mapping(pan_config, device_group, object_type, service_member_xpath)
        # Build mapping of entries to group names:
        # Equivalent groups are not an issue -> They can be deduped with a separate validator
        # However, this won't be able to detect nested groups replacements well. That can be a future enhancement.
        members_to_groupnames = {}
        for group_name, members in servicegroups_to_underlying_services.items():
            members_to_groupnames[tuple(sorted(members))] = group_name

        for ruletype in ('SecurityPreRules', 'SecurityPostRules'):
            for rule_entry in pan_config.get_devicegroup_policy(ruletype, device_group):
                count_checks+=1
                # Skip disabled rules:
                if rule_entry.find("./disabled") is not None and rule_entry.find("./disabled").text == "yes":
                    continue

                # Obtain the list of members, then normalize them so we can check for inclusion:
                service_members = tuple(sorted([elem.text for elem in rule_entry.findall('./service/member')]))
                # Check if the normalized members are already present as a ServiceGroup
                if service_members in members_to_groupnames:
                    groupname = members_to_groupnames[service_members]
                    rule_name = rule_entry.get('name')
                    text = f"Device Group {device_group}'s {ruletype} '{rule_name}' Services can be replaced with ServiceGroup: {groupname}"
                    detail={
                        "device_group":device_group,
                        "entry_type":'Address',
                        "rule_type":ruletype,
                        "rule_name":rule_name,
                        "extra":f"groupname: {groupname}"
                    }
                    badentries.append(BadEntry(data=(ruletype, rule_entry, groupname), text=text, device_group=device_group, entry_type='Address',Detail=parsed_details(detail)))
    return badentries, count_checks
