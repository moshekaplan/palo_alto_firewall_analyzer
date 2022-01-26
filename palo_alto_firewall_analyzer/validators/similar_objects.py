import collections

from palo_alto_firewall_analyzer.core import BadEntry, register_policy_validator

def find_local_similar_names(devicegroup_objects, device_group, object_type1, object_type2):
    """Finds objects in a single devicegroup which share a namespace and have names
    which are the same except for their case. For example, Address objects with similar names as other
    Address or Address Group objects in the same device group.
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

        text = f"Device Group {device_group} contains objects with similar names: {suffix_text}"
        badentries.append(BadEntry(data=dupes, text=text, device_group=device_group, entry_type=object_type1))
    return badentries

@register_policy_validator("SimilarAddressesAndGroups",
                           "Address and AddressGroup objects with similar, but different, names")
def find_similar_addresses_and_groups(profilepackage):
    device_groups = profilepackage.device_groups
    devicegroup_objects = profilepackage.devicegroup_objects

    badentries = []

    print("*" * 80)
    print("Checking for similarly-named Address and Address Group objects")

    for i, device_group in enumerate(device_groups):
        print(f"({i + 1}/{len(device_groups)}) Checking {device_group}'s address objects")
        badentries.extend(find_local_similar_names(devicegroup_objects, device_group, 'Addresses', 'AddressGroups'))
    return badentries

@register_policy_validator("SimilarServicesAndGroups",
                           "Service and ServiceGroup objects with similar, but different, names")
def find_similar_services_and_groups(profilepackage):
    device_groups = profilepackage.device_groups
    devicegroup_objects = profilepackage.devicegroup_objects

    badentries = []

    print("*" * 80)
    print("Checking for similarly-named Service and Service Group objects")

    for i, device_group in enumerate(device_groups):
        print(f"({i + 1}/{len(device_groups)}) Checking {device_group}'s Service objects")
        badentries.extend(find_local_similar_names(devicegroup_objects, device_group, 'Services', 'ServiceGroups'))
    return badentries