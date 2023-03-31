#!/usr/bin/env python

# Removes all usage of a list of Address objects and then deletes it.
# Here is a summary of the overall approach:
# 1) Start with list of address objects to remove
# 2) Build list of policies and address groups that will need to be updated
# 3) If a rule would go to zero entries - disable the rule
# 4) If an Address Group would go to zero entries - delete that and propagate to other Address Groups and policies
# 5) Repeat from step 2 until there are no more changes
# WARNING: This was not tested for situations in which there are multiple Address objects with the same name.
# Do not use this script if you have multiple Address objects with the same name

import argparse
import datetime
import os
import time


from palo_alto_firewall_analyzer import pan_api
from palo_alto_firewall_analyzer.core import ConfigurationSettings
from palo_alto_firewall_analyzer.core import xml_object_to_dict
from palo_alto_firewall_analyzer.pan_helpers import load_config_package
from palo_alto_firewall_analyzer.pan_helpers import load_API_key


DEFAULT_CONFIG_DIR = os.path.expanduser("~" + os.sep + ".pan_policy_analyzer" + os.sep)
DEFAULT_CONFIGFILE = DEFAULT_CONFIG_DIR + "PAN_CONFIG.cfg"
DEFAULT_API_KEYFILE = DEFAULT_CONFIG_DIR + "API_KEY.txt"


def extract_addresses(pan_config, devicegroup_objects, device_group):
    '''Extracts all Addresses from the Panorama configuration'''
    all_addresses = []

    for child_dg in devicegroup_objects[device_group]['all_child_device_groups']:
        for address in pan_config.get_devicegroup_object('Addresses', child_dg):
            object_dict = xml_object_to_dict(address)['entry']
            all_addresses += [{'object_dg': child_dg, 'object_type': 'Addresses', 'object_dict': object_dict}]
    return all_addresses


def extract_address_groups(pan_config, devicegroup_objects, device_group):
    '''Extracts all AddressGroups from the Panorama configuration'''
    all_addressgroups = []

    for child_dg in devicegroup_objects[device_group]['all_child_device_groups']:
        for addressgroup in pan_config.get_devicegroup_object('AddressGroups', child_dg):
            object_dict = xml_object_to_dict(addressgroup)['entry']
            all_addressgroups += [{'object_dg': child_dg, 'object_type': 'AddressGroups', 'object_dict': object_dict}]
    return all_addressgroups


def extract_policies(pan_config, devicegroup_objects, device_group):
    '''Extracts all Policies from the Panorama configuration'''
    all_policies = []

    for child_dg in devicegroup_objects[device_group]['all_child_device_groups']:
        # Then check all of the policies
        for policytype in pan_config.SUPPORTED_POLICY_TYPES:
            for policy_entry in pan_config.get_devicegroup_policy(policytype, child_dg):
                policy_dict = xml_object_to_dict(policy_entry)['entry']
                all_policies += [{'policy_dg': child_dg, 'policy_type': policytype, 'policy_dict': policy_dict}]
    return all_policies


def remove_addresses_from_addressgroups(addressgroups, addresses_to_delete):
    '''Removes the specified addresses from all address groups.
    Returns the lists of which address groups need to be updated and which
    had all entries removed and so should be deleted'''
    addressgroups_to_delete = []
    addressgroups_to_update = []

    for addressgroup_values in addressgroups:
        object_dg = addressgroup_values['object_dg']
        object_type = addressgroup_values['object_type']
        object_dict = addressgroup_values['object_dict']
        object_name = object_dict['@name']

        # Ignore AddressGroups with dynamic values; we have nothing to examine there
        if 'static' not in object_dict:
            continue

        # If it's an addressgroup with only one member, it'll be parsed as a string, not a list
        if isinstance(object_dict['static']['member'], str):
            ag_members = [object_dict['static']['member']]
        else:
            ag_members = object_dict['static']['member']

        # AddressGroups must have at least one entry, so if all of its entries are deleted,
        # the AddressGroup will also need to be deleted
        new_ag_members = sorted(set(ag_members)-addresses_to_delete)
        if len(new_ag_members) == 0:
            addressgroups_to_delete.append((object_dg, object_type, object_name))
        elif len(new_ag_members) != len(ag_members):
            addressgroups_to_update.append((object_dg, object_type, object_name))

        # Last step: Update the objects themselves with the new members
        object_dict['static']['member'] = new_ag_members

    return addressgroups_to_delete, addressgroups_to_update


def remove_addresses_from_policies(policies, addressname_to_remove):
    '''Removes the specified addresses from all policies
    Returns the lists of which policies need to be updated and which had all
    entries in a direction removed and so should be disabled'''
    policies_to_update = []
    for policy_values in policies:
        policy_dg = policy_values['policy_dg']
        policy_type = policy_values['policy_type']
        policy_dict = policy_values['policy_dict']
        policy_name = policy_dict['@name']
        for direction in ('source', 'destination'):
            # If it's a policy with only one member, it'll be parsed as a string, not a list
            if isinstance(policy_dict[direction]['member'], str):
                members = [policy_dict[direction]['member']]
            else:
                members = policy_dict[direction]['member']

            if addressname_to_remove & set(members):
                new_ag_members = sorted(set(members)-addressname_to_remove)
                if len(new_ag_members) == 0:
                    # We removed all members in a direction. The policy should be disabled.
                    policy_dict['disabled'] = 'yes'
                    # We need to set the direction's members to be 'any' so the policy is valid
                    new_ag_members = 'any'
                # Last step: Update the objects themselves with the new members
                policy_dict[direction]['member'] = new_ag_members
                policies_to_update.append((policy_dg, policy_type, policy_name))
    return policies_to_update


def delete_address_usage(profilepackage, object_type, object_friendly_type, address_dg, addresses_to_delete):
    pan_config = profilepackage.pan_config
    devicegroup_objects = profilepackage.devicegroup_objects
    panorama = profilepackage.settings.get("Panorama")
    version = pan_config.get_major_version()
    api_key = profilepackage.api_key

    # Create list of all Address Groups and Policies, since we're going to need to iterate on them multiple times
    all_addressgroups = extract_address_groups(pan_config, devicegroup_objects, address_dg)
    all_policies = extract_policies(pan_config, devicegroup_objects, address_dg)

    # Variables for storing the addressgroups and policies that will need to be updated and deleted
    all_addressgroups_to_delete = set()
    all_addressgroups_to_update = set()
    all_policies_to_update = set()

    # To make operations more efficient, convert addresses to delete as a set:
    addresses_to_delete_set = set(addresses_to_delete)

    more_to_delete = True
    while more_to_delete:
        # Determine which addressgroups should be updated and deleted
        addressgroups_to_delete, addressgroups_to_update = remove_addresses_from_addressgroups(all_addressgroups, addresses_to_delete_set)
        # Determine which policies should be updated and deleted
        policies_to_update = remove_addresses_from_policies(all_policies, addresses_to_delete_set)

        all_addressgroups_to_delete |= set(addressgroups_to_delete)
        all_addressgroups_to_update |= set(addressgroups_to_update)
        all_policies_to_update |= set(policies_to_update)

        # If we need to delete an addressgroup, we need to rerun, this time with the address groups that we'll be deleting
        more_to_delete = len(addressgroups_to_delete) > 0

    # It's possible that an address group is in both all_addressgroups_to_update and all_addressgroups_to_delete
    # For example, if an AddressGroup had two entries and both were deleted, it would first be added  to all_addressgroups_to_update
    # and afterwards be added to all_addressgroups_to_delete.
    # To avoid processing the same entries twice, skip the ones in 'update' if they're also in 'delete'
    all_addressgroups_to_update = all_addressgroups_to_update - all_addressgroups_to_delete

    # The ordering is important here:
    # First, update the rules (disabling where appropriate) so they no longer use the addresses and address groups
    # Second, update the address groups, to avoid using any contained address groups that will be deleted
    # Third, delete the address groups, to avoid using their address objects any longer
    # Fourth, delete the address objects themselves
    # TODO: If an AddressGroup A contains a single AddressGroup B, it would be important that A be deleted before B,
    # because otherwise B's deletion would fail. This edge case is not currently being handled.
    # One possible solution would be to be sensitive to the ordering in which AddressGroups are added
    # to the list of what should be deleted, and ensuring they are deleted in that order.
    # While doable, that would require restructuring the loop for deletion below.
    print("Updating Policies")
    for policy_values in all_policies:
        policy_dg = policy_values['policy_dg']
        policy_type = policy_values['policy_type']
        policy_dict = policy_values['policy_dict']

        policy_name = policy_dict['@name']
        if (policy_dg, policy_type, policy_name) in all_policies_to_update:
            print(f"Updating {policy_dg}'s {policy_type} {policy_name}")
            pan_api.update_devicegroup_policy(panorama, version, api_key, policy_dict, policy_type, policy_dg)

    print("Updating AddressGroups")
    for addressgroup_values in all_addressgroups:
        object_dg = addressgroup_values['object_dg']
        object_type = addressgroup_values['object_type']
        object_dict = addressgroup_values['object_dict']
        object_name = object_dict['@name']
        if (object_dg, object_type, object_name) in all_addressgroups_to_update:
            print(f"Updating {object_dg}'s {object_type} {object_name}")
            pan_api.update_devicegroup_object(panorama, version, api_key, object_dict, object_type, object_dg)

    print("Deleting AddressGroups")
    for addressgroup_values in all_addressgroups:
        object_dg = addressgroup_values['object_dg']
        object_type = addressgroup_values['object_type']
        object_dict = addressgroup_values['object_dict']
        object_name = object_dict['@name']
        if (object_dg, object_type, object_name) in all_addressgroups_to_delete:
            print(f"Deleting {object_dg}'s {object_type} {object_name}")
            pan_api.delete_object(panorama, version, api_key, object_type, object_dict, object_dg)

    print("Deleting Addresses")
    # Only delete address objects which exist, otherwise the additional API reqeusts
    # will make the script take longer to run and will return errors that might
    # worry the user
    addresses_to_delete_that_exist = []
    all_addresses = extract_addresses(pan_config, devicegroup_objects, address_dg)
    for address_values in all_addresses:
        object_dg = address_values['object_dg']
        object_dict = address_values['object_dict']
        object_name = object_dict['@name']
        if object_dg == address_dg and object_name in addresses_to_delete:
            addresses_to_delete_that_exist.append(object_name)

    for address_name in addresses_to_delete_that_exist:
        print(f"Deleting {address_dg}'s Addresses {address_name}")
        pan_api.delete_object(panorama, version, api_key, 'Addresses', address_name, address_dg)

    return


def main():
    parser = argparse.ArgumentParser(description="Deletes a list of Addresses read from a file")
    parser.add_argument("--device-group", help="Device Group to containing object", required=True)
    parser.add_argument("--object-type", help="Type of object", required=True)
    parser.add_argument("--infile", help="Input file with list of Address objects to delete", required=True)
    parser.add_argument("--config", help=f"Config file to read (default is {DEFAULT_CONFIGFILE})", default=DEFAULT_CONFIGFILE)
    parser.add_argument("--api", help=f"File with API Key (default is {DEFAULT_API_KEYFILE})", default=DEFAULT_API_KEYFILE)
    parser.add_argument("--debug", help="Write all debug output to pan_analyzer_debug_YYMMDD_HHMMSS.log", action='store_true')
    parsed_args = parser.parse_args()

    timestamp_string = datetime.datetime.today().strftime('%Y%m%d_%H%M%S')
    if parsed_args.debug:
        pan_api.set_debug(True, f'pan_analyzer_debug_{timestamp_string}.log')

    api_key = load_API_key(parsed_args.api)

    if not os.path.isfile(parsed_args.config):
        if parsed_args.config == DEFAULT_CONFIGFILE:
            ConfigurationSettings().write_config(parsed_args.config)
            raise Exception(f"Config file '{parsed_args.config}' did not exist! Creating {parsed_args.config}. Update the value for 'panorama' before re-running")
            return 1
        else:
            raise Exception(f"Config file '{parsed_args.config}' does not exist! Exiting")

    configuration_settings = ConfigurationSettings(parsed_args.config).get_config()

    start_time = time.time()
    profilepackage = load_config_package(configuration_settings, api_key, parsed_args.device_group, None, '')

    object_type = "Addresses"
    object_friendly_type = "Address"
    object_dg = parsed_args.device_group
    with open(parsed_args.infile) as fh:
        addresses_to_delete = set(fh.read().splitlines())
    delete_address_usage(profilepackage, object_type, object_friendly_type, object_dg, addresses_to_delete)

    end_time = time.time()

    print("*" * 80)
    print(f"Full run took {end_time - start_time} seconds")

    return


if __name__ == '__main__':
    main()
