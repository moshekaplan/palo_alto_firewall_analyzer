import collections
import logging

from palo_alto_firewall_analyzer.core import BadEntry, register_policy_validator
from palo_alto_firewall_analyzer.scripts.pan_details import parsed_details

logger = logging.getLogger(__name__)

@register_policy_validator("ShadowingAddressesAndGroups",
                           "Address and AddressGroup objects that have the same name and shadow each other")
def find_shadowing_addresses_and_groups(profilepackage):
    device_groups = profilepackage.device_groups
    devicegroup_objects = profilepackage.devicegroup_objects
    device_group_hierarchy_parent = profilepackage.device_group_hierarchy_parent
    rule_limit_enabled = profilepackage.rule_limit_enabled

    if rule_limit_enabled:
        return []

    badentries = []
    count_checks = 0
    
    logger.info("*" * 80)
    logger.info("Checking for shadowing Address and Address Group objects")

    for i, device_group in enumerate(device_groups):
        logger.info(f"({i + 1}/{len(device_groups)}) Checking {device_group}'s address objects")
        object_entries = {}
        object_entries['Addresses'] = {entry.get('name'): (device_group, 'Addresses', entry) for entry in devicegroup_objects[device_group]['Addresses']}
        object_entries['AddressGroups'] = {entry.get('name'): (device_group, 'AddressGroups', entry) for entry in devicegroup_objects[device_group]['AddressGroups']}

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
            for address in devicegroup_objects[parent_dg]['Addresses']:
                addresses_in_use[address.get('name')].append((parent_dg, 'Addresses', address))
            # Then check all parent Address Groups
            for address_group in devicegroup_objects[parent_dg]['AddressGroups']:
                addressgroups_in_use[address_group.get('name')].append((parent_dg, 'AddressGroups', address_group))

        # Three separate types of 'shadowing' are possible:
        # Address objects with names present in a parent device group
        # Address Group objects with names present in a parent device group
        # Address objects with the same names as the Address Group objects in the current device group
        # These are each processed separately
        names_in_use = set(addresses_in_use.keys()) | set(addressgroups_in_use.keys())
        shadowed_objects_mappings = {}
        shadowed_objects_mappings['Addresses'] = sorted(set(object_entries['Addresses'].keys()) & names_in_use)
        shadowed_objects_mappings['AddressGroups'] = sorted(set(object_entries['AddressGroups'].keys()) & names_in_use)
        local_shadowing_names = sorted(set(object_entries['Addresses'].keys()) & set(object_entries['AddressGroups'].keys()))

        # Address objects with names present in a parent device group
        obj_types = ['Addresses', 'AddressGroups']
        for obj_type in obj_types:
            shadowed_objects = shadowed_objects_mappings[obj_type]
            for shadowing_address_name in shadowed_objects:
                shadowing_addresses = addresses_in_use[shadowing_address_name]
                shadowing_addressgroups = addressgroups_in_use[shadowing_address_name]

                address_dgs = [entry[0] for entry in shadowing_addresses]
                addressgroup_dgs = [entry[0] for entry in shadowing_addressgroups]
                address_dg_text = f"as an Address in Device Groups: {address_dgs}"
                addressgroup_dg_text = f"as an Address Group in Device Groups: {addressgroup_dgs}"
                if shadowing_addresses and shadowing_addressgroups:
                    suffix_text = address_dg_text + " and " + addressgroup_dg_text
                elif shadowing_addresses:
                    suffix_text = address_dg_text
                elif shadowing_addressgroups:
                    suffix_text = addressgroup_dg_text
                else:
                    raise Exception("Shouldn't be possible to not have any Device Groups!")

                data = [object_entries[obj_type][shadowing_address_name]] + shadowing_addresses + shadowing_addressgroups
                text = f"Device Group {device_group}'s {obj_type} {shadowing_address_name} is already present {suffix_text}"
                detail={
                    "device_group":device_group,
                    "entry_type":obj_type,
                    "shadowing_address_name":shadowing_address_name                    
                }
                badentries.append(
                    BadEntry(data=data, text=text, device_group=device_group, entry_type=obj_type,Detail=parsed_details(detail)))
                count_checks+=1
                
        for local_overlap in local_shadowing_names:
            text = f"Device Group {device_group}'s contains both an Address and Address Group with the same name of '{local_overlap}' Address: {object_entries['Addresses'][local_overlap]}, AddressGroups: {object_entries['AddressGroups'][local_overlap]}"
            data = [object_entries['AddressGroups'][local_overlap],object_entries['Addresses'][local_overlap]]
            detail={
                "device_group":device_group,
                "entry_type":'Addresses',
                "extra": f"local_overlap: {local_overlap}, Address: {object_entries['Addresses'][local_overlap]}, AddressGroups: {object_entries['AddressGroups'][local_overlap]}"
            }
            badentries.append(BadEntry(data=data, text=text, device_group=device_group,
                                       entry_type='Addresses',Detail=parsed_details(detail)))
            count_checks+=1

    return badentries,count_checks