import collections
import functools
import json
import xml.etree.ElementTree

import xmltodict

from palo_alto_firewall_analyzer.core import BadEntry, register_policy_validator

def normalize_address(addr_dict):
    # Append /32 to IPv4 addresses
    if 'ip-netmask' in addr_dict['entry'] and '.' in addr_dict['entry']['ip-netmask'] and '/' not in addr_dict['entry']['ip-netmask']:
        addr_dict['entry']['ip-netmask'] += "/32"
    return addr_dict

def normalize_addressgroup(addr_dict):
    # Sort the members of static address group objects
    if 'static' in addr_dict['entry']:
        addr_dict['entry']['static']['member'] = sorted(addr_dict['entry']['static']['member'])
    return addr_dict

def normalize_servicegroup(addr_dict):
    # Sort the members of service group objects
    addr_dict['entry']['members']['member'] = sorted(addr_dict['entry']['members']['member'])
    return addr_dict

NORMALIZATION_FUNCTIONS = {'Addresses': normalize_address,
                           'AddressGroups': normalize_addressgroup,
                           'ServiceGroups': normalize_servicegroup,
                           }

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

    if object_type in NORMALIZATION_FUNCTIONS:
        normalized_dict = NORMALIZATION_FUNCTIONS[object_type](normalized_dict)

    return json.dumps(normalized_dict, sort_keys=True)


def find_equivalent_objects(profilepackage, object_type):
    """
    Generic function for finding all objects in the hierarchy with effectively the same values
    """
    device_groups = profilepackage.device_groups
    devicegroup_objects = profilepackage.devicegroup_objects
    device_group_hierarchy_parent = profilepackage.device_group_hierarchy_parent

    badentries = []

    print("*" * 80)
    print(f"Checking for equivalent {object_type} objects")

    for i, device_group in enumerate(device_groups):
        print(f"({i + 1}/{len(device_groups)}) Checking {device_group}'s address objects")
        # An object can be inherited from any parent device group. Need to check all of them.
        # Basic strategy: Normalize all objects, then report on the subset present in this device group
        parent_dgs = []
        current_dg = device_group_hierarchy_parent.get(device_group)
        while current_dg:
            parent_dgs.append(current_dg)
            current_dg = device_group_hierarchy_parent.get(current_dg)

        all_equivalent_objects = collections.defaultdict(list)
        for dg in parent_dgs:
            for obj in devicegroup_objects[dg][object_type]:
                object_data = normalize_object(obj, object_type)
                all_equivalent_objects[object_data].append((dg, obj))

        local_equivalencies = set()
        for obj in devicegroup_objects[device_group][object_type]:
            object_data = normalize_object(obj, object_type)
            local_equivalencies.add(object_data)
            all_equivalent_objects[object_data].append((device_group, obj))

        equivalencies_to_examine = sorted(set(local_equivalencies) & set(all_equivalent_objects.keys()))

        for equivalencies in equivalencies_to_examine:
            entries = all_equivalent_objects[equivalencies]
            if len(entries) >= 2:
                equivalency_texts = []
                for dg, obj in entries:
                    equivalency_text = f'Device Group: {dg}, Name: {obj.get("name")}'
                    equivalency_texts.append(equivalency_text)
                text = f"Device Group {device_group} has the following equivalent {object_type}: {equivalency_texts}"
                badentries.append(BadEntry(data=entries, text=text, device_group=device_group, entry_type=object_type))
    return badentries


@register_policy_validator("EquivalentAddresses", "Addresses objects that are equivalent with each other")
def find_equivalent_addresses(profilepackage):
    return find_equivalent_objects(profilepackage, "Addresses")

@register_policy_validator("EquivalentAddressGroups", "Address Group objects that are equivalent with each other")
def find_equivalent_addressesgroups(profilepackage):
    return find_equivalent_objects(profilepackage, "AddressGroups")

@register_policy_validator("EquivalentServices", "Service objects that are equivalent with each other")
def find_equivalent_services(profilepackage):
    return find_equivalent_objects(profilepackage, "Services")

@register_policy_validator("EquivalentServiceGroups", "Service Group objects that are equivalent with each other")
def find_equivalent_servicegroups(profilepackage):
    return find_equivalent_objects(profilepackage, "ServiceGroups")