import collections
import functools
import json
import logging
import xml.etree.ElementTree

import xmltodict

from palo_alto_firewall_analyzer.core import BadEntry, register_policy_validator
from palo_alto_firewall_analyzer.scripts.pan_details import parsed_details

logger = logging.getLogger(__name__)

@functools.lru_cache(maxsize=None)
def normalize_object(obj, object_type):
    """Turn an XML-based object into a
    normalized string representation.

    We normalize the XML object by
    converting the object to a dictionary,
    deleting the keys we don't want to look at,
    and then converting the dictionary to a string"""
    xml_string = xml.etree.ElementTree.tostring(obj)
    normalized_dict = xmltodict.parse(xml_string)

    # Specifically don't look at the name, or every object would be unique
    del normalized_dict['entry']['@name']

    return json.dumps(normalized_dict, sort_keys=True)

def find_shadowing_objects(profilepackage, object_type):
    device_groups = profilepackage.device_groups
    devicegroup_objects = profilepackage.devicegroup_objects
    device_group_hierarchy_parent = profilepackage.device_group_hierarchy_parent

    badentries = []
    count_checks = 0

    logger.info("*" * 80)
    logger.info(f"Checking for shadowing {object_type} objects")

    for i, device_group in enumerate(device_groups):
        logger.info(f"({i + 1}/{len(device_groups)}) Checking {device_group}'s address objects")
        names_to_obj = {entry.get('name'): entry for entry in devicegroup_objects[device_group][object_type]}

        # An object can be inherited from any parent device group. Need to check all of them.
        names_to_dg_obj_from_parent_dgs = collections.defaultdict(list)

        parent_dgs = []
        current_dg = device_group_hierarchy_parent.get(device_group)
        while current_dg:
            parent_dgs.append(current_dg)
            current_dg = device_group_hierarchy_parent.get(current_dg)

        for parent_dg in parent_dgs:
            for obj in devicegroup_objects[parent_dg][object_type]:
                names_to_dg_obj_from_parent_dgs[obj.get('name')].append((parent_dg, obj))

        overlapping_names = sorted(set(names_to_obj.keys()) & set(names_to_dg_obj_from_parent_dgs.keys()))

        for overlapping_name in overlapping_names:
            local_obj = names_to_obj[overlapping_name]
            normalized_obj = normalize_object(local_obj, object_type)

            unique_device_groups = set()
            shadowed_objects = [local_obj]
            normalized_objects = set([normalized_obj])
            for dg, obj in names_to_dg_obj_from_parent_dgs[overlapping_name]:
                unique_device_groups.add(dg)
                shadowed_objects.append(obj)
                normalized_objects.add(normalize_object(obj, object_type))

            all_consistent = len(normalized_objects) == 1
            sorted_dgs = sorted(unique_device_groups)

            if all_consistent:
                same_text = "and the contents are equivalent"
            else:
                same_text = "and the contents are NOT equivalent"
            data = names_to_dg_obj_from_parent_dgs[overlapping_name] + [[device_group, local_obj]]
            text = f"Device Group {device_group}'s {object_type} '{overlapping_name}' is already present in Device Group {sorted_dgs} {same_text}"
            detail = {
                "device_group": device_group,
                "entry_type": object_type,
                "extra": f"sorted_dgs: {sorted_dgs}, text: {same_text}, overlapping_name: {overlapping_name}"
            }
            badentries.append(
                BadEntry(data=data, text=text, device_group=device_group, entry_type=object_type, Detail=parsed_details(detail)))
            count_checks += 1
            
    return badentries, count_checks


@register_policy_validator("ShadowingServices", "Service objects that have the same name and shadow each other")
def find_shadowing_services(profilepackage):
    return find_shadowing_objects(profilepackage, "Services")


@register_policy_validator("ShadowingServiceGroups",
                           "Service Group objects that have the same name and shadow each other")
def find_shadowing_service_groups(profilepackage):
    return find_shadowing_objects(profilepackage, "ServiceGroups")
