import collections
import copy
import logging

from palo_alto_firewall_analyzer.core import BadEntry, register_policy_validator, get_policy_validators, xml_object_to_dict

logger = logging.getLogger(__name__)

def find_objects_needing_consolidation(equivalent_objects):
    # Takes as input the results from EquivalentAddresses
    # Returns a mapping of device groups to lists of objects that need to be consolidated
    objects_to_consolidate = collections.defaultdict(list)
    for entries in equivalent_objects:
        dg_to_objects = collections.defaultdict(list)
        for dg, contents in entries.data:
            dg_to_objects[dg].append(contents)
        for dg, equivalencies in dg_to_objects.items():
            if len(equivalencies) > 1:
                objects_to_consolidate[dg].append([equivalency.get('name') for equivalency in equivalencies])
    return objects_to_consolidate

def find_replacement_objects(pan_config, devicegroup_objects, device_group, objects_to_consolidate):
    # Track where each object is used, so we can determine which object is most commonly-used
    # and minimize the amount of changes that will be needed
    # Returns a mapping of object names to the object that should replace them
    # It is inefficient to iterate through the rules twice, but this keeps
    # the code much cleaner and anyways shouldn't take too long, compared to
    # the API calls it will help save
    addresses_to_counts = collections.Counter()
    for child_dg in devicegroup_objects[device_group]['all_child_device_groups']:
        # First check all child Address Groups
        for addressgroup in pan_config.get_devicegroup_object('AddressGroups', child_dg):
            for member_element in addressgroup.findall('./static/member'):
                addresses_to_counts[member_element.text] += 1
        # Then check all of the policies
        for policytype in pan_config.SUPPORTED_POLICY_TYPES:
            for policy_entry in pan_config.get_devicegroup_policy(policytype, child_dg):
                for member in policy_entry.findall('./*/member'):
                    addresses_to_counts[member.text] += 1

    # Then determine to determine which object will be used, create a mapping of old names to new names
    old_addresses_to_replacements = {}
    for addresses_to_consolidate in objects_to_consolidate:
        most_common_address = max(addresses_to_consolidate, key=lambda x: addresses_to_counts[x])
        for address in addresses_to_consolidate:
            if address != most_common_address:
                old_addresses_to_replacements[address] = most_common_address
    return old_addresses_to_replacements

def find_objects_policies_needing_replacement(pan_config, devicegroup_objects, device_group, address_to_replacement):
    addresses_to_replace = set(address_to_replacement.keys())
    addressgroups_needing_replacement = []
    policies_needing_replacement = []

    for child_dg in devicegroup_objects[device_group]['all_child_device_groups']:
        # First check all child Address Groups
        for addressgroup in pan_config.get_devicegroup_object('AddressGroups', child_dg):
            for member_element in addressgroup.findall('./static/member'):
                if member_element.text in addresses_to_replace:
                    addressgroups_needing_replacement += [(child_dg, 'AddressGroups', addressgroup)]
                    break
        # Then check all of the policy's referenced members
        xml_paths = ['./*/member',
                     './*/dynamic-ip-and-port/translated-address/member',
                     './*/translated-address',
                     './*/static-ip/translated-address']
        for policytype in pan_config.SUPPORTED_POLICY_TYPES:
            for policy_entry in pan_config.get_devicegroup_policy(policytype, child_dg):
                # Skip disabled policies
                if policy_entry.find('disabled') is not None and policy_entry.find('disabled').text == 'yes':
                    continue
                found = False
                for xml_path in xml_paths:
                    for address_member_element in policy_entry.findall(xml_path):
                        if address_member_element.text in addresses_to_replace:
                            policies_needing_replacement += [(child_dg, policytype, policy_entry)]
                            found = True
                            break
                    if found:
                        break
    return addressgroups_needing_replacement, policies_needing_replacement


def replace_addressgroup_contents(addressgroups_needing_replacement, address_to_replacement):
    badentries = []
    for object_dg, object_type, object_entry in addressgroups_needing_replacement:
        object_policy_dict = xml_object_to_dict(object_entry)['entry']
        new_addresses = []
        replacements_made = {}

        # If it's an addressgroup with only one member, it'll be parsed as a string, not a list
        if isinstance(object_policy_dict['static']['member'], str):
            member_to_replace = object_policy_dict['static']['member']
            replacements_made[member_to_replace] = address_to_replacement[member_to_replace]
            new_addresses.append(address_to_replacement[member_to_replace])
        else:
            for member in object_policy_dict['static']['member']:
                if member in new_addresses:
                    # Member is already present, nothing to do
                    continue
                elif member not in address_to_replacement:
                    # Member is not present and doesn't need to be replaced, so keep it as is:
                    new_addresses.append(member)
                elif member in address_to_replacement and address_to_replacement[member] not in new_addresses:
                    # Member needs to be replaced, and replacement is not already present, so add it:
                    new_addresses.append(address_to_replacement[member])
                    replacements_made[member] = address_to_replacement[member]
                else:
                    # Member needs to be replaced, but replacement is already present, so nothing to do:
                    continue
        assert object_policy_dict['static']['member'] != new_addresses

        object_policy_dict['static']['member'] = new_addresses
        text = f"Replace the following Address members in {object_dg}'s {object_type} {object_entry.get('name')}: {sorted([k + ' with ' + v for k, v in replacements_made.items()])}"
        badentries.append(BadEntry(data=[object_entry, object_policy_dict], text=text, device_group=object_dg, entry_type=object_type))
    return badentries

def replace_member_contents(address_like_entries, address_to_replacement, replacements_made):
    replacements_made = copy.deepcopy(replacements_made)
    # member_entry is either a string for a single object, or a list if there
    # are two or more objects
    if isinstance(address_like_entries, str):
        if address_like_entries in address_to_replacement:
            replacements_made[address_like_entries] = address_to_replacement[address_like_entries]
            return address_to_replacement[address_like_entries], replacements_made
        else:
            return address_like_entries, replacements_made
    else:
        # Iterate through the policy's members to see which need to be replaced, and
        # with what. Then store what changed in replacements_made
        new_addresses = []
        for member in address_like_entries:
            if member in new_addresses:
                # Member is already present, nothing to do
                continue
            elif member not in address_to_replacement:
                # Member is not present and doesn't need to be replaced, so keep it as is:
                new_addresses.append(member)
            elif member in address_to_replacement and address_to_replacement[member] not in new_addresses:
                # Member needs to be replaced, and replacement is not already present, so add it:
                replacements_made[member] = address_to_replacement[member]
                new_addresses.append(address_to_replacement[member])
            else:
                # Member needs to be replaced, but replacement is already present, so member will not be added:
                replacements_made[member] = "<NOTHING>"
                continue
        # Note that it's possible for there to be no replacements made, because the replacing was
        # only needed in 'source', not 'destination', or vice-versa
        # If no replacements were made, than object_policy_dict[direction]['member'] = new_addresses will not
        # actually result in any change - but that's fine, because it's still one API request for the
        # other members and since this hasn't modified, it won't muddy up the diff
        return new_addresses, replacements_made


def replace_policy_contents(policies_needing_replacement, address_to_replacement):
    badentries = []
    for policy_dg, policy_type, policy_entry in policies_needing_replacement:
        object_policy_dict = xml_object_to_dict(policy_entry)['entry']
        replacements_made = {}
        for direction in ('source', 'destination'):
            object_policy_dict[direction]['member'], replacements_made = replace_member_contents(object_policy_dict[direction]['member'], address_to_replacement, replacements_made)

        # Extra places to check for NAT objects:
        if policy_type in ("NATPreRules", "NATPostRules"):
            for translation in ('source-translation', 'destination-translation'):
                if translation not in object_policy_dict:
                    continue
                if object_policy_dict[translation].get('translated-address'):
                    object_policy_dict[translation]['translated-address'], replacements_made = replace_member_contents(object_policy_dict[translation]['translated-address'], address_to_replacement, replacements_made)
                if object_policy_dict[translation].get('dynamic-ip-and-port', {}).get('translated-address', {}).get('member'):
                    object_policy_dict[translation]['dynamic-ip-and-port']['translated-address']['member'], replacements_made = replace_member_contents(object_policy_dict[translation]['dynamic-ip-and-port']['translated-address']['member'], address_to_replacement, replacements_made)
                if object_policy_dict[translation].get('static-ip', {}).get('translated-address', {}).get('member'):
                    object_policy_dict[translation]['static-ip']['translated-address']['member'], replacements_made = replace_member_contents(object_policy_dict[translation]['static-ip']['translated-address']['member'], address_to_replacement, replacements_made)
        text = f"Replace the following Address members in {policy_dg}'s {policy_type} {policy_entry.get('name')}: {sorted([k + ' with ' + v for k, v in replacements_made.items()])}"
        badentries.append(BadEntry(data=[policy_entry, object_policy_dict], text=text, device_group=policy_dg, entry_type=policy_type))
    return badentries

def consolidate_address_like_objects(profilepackage, object_type, object_friendly_type, validator_function):
    pan_config = profilepackage.pan_config
    devicegroup_objects = profilepackage.devicegroup_objects

    logger.info ("*"*80)
    logger.info (f"Checking for {object_friendly_type} objects to consolidate")

    # Objects will only be consolidated at the same device group level, to avoid potential scope issues
    equivalent_objects = validator_function(profilepackage)
    dg_to_objects_to_consolidate = find_objects_needing_consolidation(equivalent_objects)
    if not dg_to_objects_to_consolidate:
        logger.info (f"There were no {object_friendly_type} to consolidate")
        return dg_to_objects_to_consolidate

    badentries = []
    for device_group, objects_to_consolidate in dg_to_objects_to_consolidate.items():
        # Determine which object is most commonly-used to minimize the amount of changes that will be needed
        address_to_replacement = find_replacement_objects(pan_config, devicegroup_objects, device_group, objects_to_consolidate)
        # Get the list of objects that will need to be updated:
        addressgroups_needing_replacement, policies_needing_replacement = find_objects_policies_needing_replacement(pan_config, devicegroup_objects, device_group, address_to_replacement)
        # Now that we know which objects need replacements, we can iterate through
        # and make those replacements!
        # First replace the contents of addressgroups
        badentries += replace_addressgroup_contents(addressgroups_needing_replacement, address_to_replacement)
        # Then replace the contents of policies
        badentries += replace_policy_contents(policies_needing_replacement, address_to_replacement)

    return badentries

@register_policy_validator("FindConsolidatableAddresses", "Consolidate use of equivalent Address objects so only one object is used")
def find_consolidatable_addresses(profilepackage):
    object_type = "Addresses"
    object_friendly_type = "Address"
    _, _, validator_function = get_policy_validators()['EquivalentAddresses']
    return consolidate_address_like_objects(profilepackage, object_type, object_friendly_type, validator_function)

@register_policy_validator("FindConsolidatableAddressGroups", "Consolidate use of equivalent AddressGroup objects so only one object is used")
def find_consolidatable_addressgroups(profilepackage):
    object_type = "AddressGroups"
    object_friendly_type = "Address Group"
    _, _, validator_function = get_policy_validators()['EquivalentAddressGroups']
    return consolidate_address_like_objects(profilepackage, object_type, object_friendly_type, validator_function)
