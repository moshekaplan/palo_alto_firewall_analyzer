import collections

from palo_alto_firewall_analyzer.core import BadEntry, register_policy_validator

def find_local_similar_names(devicegroup_objects, device_group, object_type1, object_type2):
    """Finds objects in a single devicegroup which have names which conflict with each other.
    For example, Address objects with similar names as other
    Address or Address Group objects in the current device group
    """
    names_to_objects = collections.defaultdict(list)
    for obj_type in [object_type1, object_type2]:
        for local_obj in devicegroup_objects[device_group][obj_type]:
            local_obj_name = local_obj.get('name')
            names_to_objects[local_obj_name.lower()].append((device_group, obj_type, local_obj))

    badentries = []
    for _, dupes in names_to_objects.items():
        if len(dupes) == 1:
            continue
        obj1s = [entry[2].get('name') for entry in dupes if entry[1] == object_type1]
        obj1s_text = f"{object_type1}: {obj1s}"
        obj2s = [entry[2].get('name') for entry in dupes if entry[1] == object_type2]
        obj2s_text = f"{object_type2}: {obj2s}"

        if obj1s and obj2s:
            suffix_text = obj1s_text + " and " + obj2s_text
        elif obj1s:
            suffix_text = obj1s_text
        elif obj2s:
            suffix_text = obj2s_text

        text = f"Device Group {device_group}'s contains objects with similar names: {suffix_text}"
        badentries.append(BadEntry(data=dupes, text=text, device_group=device_group, entry_type=object_type1))
    return badentries

def find_similar_names_in_devicegroups(devicegroup_objects, device_group_hierarchy_parent, device_group,
                                       object_type1, object_type2):
    """Finds objects which conflict with another similar object in the device group hierarchy.
    For example, Address objects with similar names as other
    Address or Address Group objects in a parent device group"""

    badentries = []
    # An address or group can be inherited from any parent device group's Address group or policy.
    # Need to check all parent device groups.
    parent_dgs = []
    current_dg = device_group_hierarchy_parent.get(device_group)
    while current_dg:
        parent_dgs.append(current_dg)
        current_dg = device_group_hierarchy_parent.get(current_dg)

    addresses_in_use = collections.defaultdict(list)
    addressgroups_in_use = collections.defaultdict(list)
    for parent_dg in parent_dgs:
        # First check all parent Addresses
        for address in devicegroup_objects[parent_dg][object_type1]:
            addresses_in_use[address.get('name').lower()].append((parent_dg, object_type1, address))
        # Then check all parent Address Groups
        for address_group in devicegroup_objects[parent_dg][object_type2]:
            addressgroups_in_use[address_group.get('name').lower()].append((parent_dg, object_type2, address_group))

    for obj_type in [object_type1, object_type2]:
        local_objs = devicegroup_objects[device_group][obj_type]
        for local_obj in local_objs:
            local_obj_name = local_obj.get('name')
            conflicting_addresses = []
            if local_obj_name.lower() in addresses_in_use:
                # Only look for conflicts where the names are different
                for addr_entry in addresses_in_use[local_obj_name.lower()]:
                    if addr_entry[2] != local_obj_name:
                        conflicting_addresses.append(addr_entry)
            conflicting_addressgroups = []
            if local_obj_name.lower() in addressgroups_in_use:
                # Only look for conflicts where the names are different
                for addr_entry in addressgroups_in_use[local_obj_name.lower()]:
                    if addr_entry[2] != local_obj_name:
                        conflicting_addressgroups.append(addr_entry)

            if not conflicting_addresses and not conflicting_addressgroups:
                # No conflicts = no problems
                continue

            address_tuples = [(entry[0], entry[2].get('name')) for entry in conflicting_addresses]
            address_dg_text = f"{object_type1}: {address_tuples}"
            addressgroup_tuples = [(entry[0], entry[2].get('name')) for entry in conflicting_addressgroups]
            addressgroup_dg_text = f"{object_type2}: {addressgroup_tuples}"
            if conflicting_addresses and conflicting_addressgroups:
                suffix_text = address_dg_text + " and " + addressgroup_dg_text
            elif conflicting_addresses:
                suffix_text = address_dg_text
            elif conflicting_addressgroups:
                suffix_text = addressgroup_dg_text

            local_entry = [(device_group, obj_type, local_obj)]
            data = local_entry + conflicting_addresses + conflicting_addressgroups
            text = f"Device Group {device_group}'s {obj_type} {local_obj_name} is similar to {suffix_text}"
            badentries.append(
                BadEntry(data=data, text=text, device_group=device_group, entry_type=obj_type))
    return badentries


@register_policy_validator("SimilarAddressesAndGroups",
                           "Address and AddressGroup objects with similar (but not equal) names")
def find_similar_addresses_and_groups(profilepackage):
    device_groups = profilepackage.device_groups
    devicegroup_objects = profilepackage.devicegroup_objects
    device_group_hierarchy_parent = profilepackage.device_group_hierarchy_parent

    badentries = []

    print("*" * 80)
    print("Checking for similarly-named Address and Address Group objects")

    for i, device_group in enumerate(device_groups):
        print(f"({i + 1}/{len(device_groups)}) Checking {device_group}'s address objects")

        # Three separate types of 'similarities' are possible:
        # Address objects with similar names as other Address or Address Group objects in the current device group
        badentries.extend(find_local_similar_names(devicegroup_objects, device_group, 'Addresses', 'AddressGroups'))
        # Address objects with names similar to an Address or Address Group in a parent device group
        # Address Group objects with names similar to an Address or Address Group in a parent device group
        badentries.extend(find_similar_names_in_devicegroups(devicegroup_objects, device_group_hierarchy_parent,
                                                             device_group, 'Addresses', 'AddressGroups'))

    return badentries