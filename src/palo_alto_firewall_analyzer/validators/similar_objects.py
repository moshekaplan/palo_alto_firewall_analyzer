import collections
import logging

from palo_alto_firewall_analyzer.core import BadEntry, register_policy_validator
from palo_alto_firewall_analyzer.scripts.pan_details import parsed_details

logger = logging.getLogger(__name__)

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
    count_checks = 0
    for _, dupes in names_to_objects.items():
        count_checks+=1
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
        detail={
            "device_group":device_group,
            "entry_type": object_type1,
            "extra":f"suffix_text: {suffix_text}"
        }
        badentries.append(BadEntry(data=dupes, text=text, device_group=device_group, entry_type=object_type1,Detail=parsed_details(detail)))
        
    return badentries,count_checks

@register_policy_validator("SimilarAddressesAndGroups",
                           "Address and AddressGroup objects with similar, but different, names")
def find_similar_addresses_and_groups(profilepackage):
    device_groups = profilepackage.device_groups
    devicegroup_objects = profilepackage.devicegroup_objects

    badentries = []
    count_checks = 0
    logger.info("*" * 80)
    logger.info("Checking for similarly-named Address and Address Group objects")

    for i, device_group in enumerate(device_groups):
        logger.info(f"({i + 1}/{len(device_groups)}) Checking {device_group}'s address objects")
        badentries_ret,count_checks_ret = find_local_similar_names(devicegroup_objects, device_group, 'Addresses', 'AddressGroups')
        count_checks+=count_checks_ret
        badentries.extend(badentries_ret)
        #badentries.extend(find_local_similar_names(devicegroup_objects, device_group, 'Addresses', 'AddressGroups'))
    return badentries,count_checks

@register_policy_validator("SimilarServicesAndGroups",
                           "Service and ServiceGroup objects with similar, but different, names")
def find_similar_services_and_groups(profilepackage):
    device_groups = profilepackage.device_groups
    devicegroup_objects = profilepackage.devicegroup_objects

    badentries = []
    count_checks = 0
    
    logger.info("*" * 80)
    logger.info("Checking for similarly-named Service and Service Group objects")

    for i, device_group in enumerate(device_groups):
        logger.info(f"({i + 1}/{len(device_groups)}) Checking {device_group}'s Service objects")
        badentries_ret,count_checks_ret = find_local_similar_names(devicegroup_objects, device_group, 'Services', 'ServiceGroups')
        count_checks+=count_checks_ret
        badentries.extend(badentries_ret)
        #badentries.extend(find_local_similar_names(devicegroup_objects, device_group, 'Services', 'ServiceGroups'))
    return badentries,count_checks