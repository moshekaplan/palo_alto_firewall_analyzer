from palo_alto_firewall_analyzer.core import BadEntry, register_policy_validator


@register_policy_validator("UnusedAddresses", "Address objects that aren't in use")
def find_unused_addresses(profilepackage):
    device_groups = profilepackage.device_groups
    devicegroup_objects = profilepackage.devicegroup_objects
    pan_config = profilepackage.pan_config

    badentries = []

    print ("*"*80)
    print ("Checking for unused Address objects")

    for i, device_group in enumerate(device_groups):
        print (f"({i+1}/{len(device_groups)}) Checking {device_group}'s address objects")
        addresses = {entry.get('name'):entry for entry in devicegroup_objects[device_group]['Addresses']}

        # An address or group can be used by any child device group's Address group or policy. Need to check all of them.
        addresses_and_groups_in_use = set()
        child_dgs = devicegroup_objects[device_group]['all_child_device_groups']
        for child_dg in child_dgs:
            # First check all child Address Groups
            for address_group in devicegroup_objects[child_dg]['AddressGroups']:
                for address_group_elem in address_group.findall('./static/member'):
                    addresses_and_groups_in_use.add(address_group_elem.text)
            # Then check all of the policies. As a note, policies use a mix of addresses and address groups
            for policytype in pan_config.SUPPORTED_POLICY_TYPES:
                policies = devicegroup_objects[child_dg][policytype]
                for policy_entry in policies:
                    for src_elem in policy_entry.findall('./source/member'):
                        addresses_and_groups_in_use.add (src_elem.text)
                    for dest_elem in policy_entry.findall('./destination/member'):
                        addresses_and_groups_in_use.add(dest_elem.text)
                    # Special fields only in NAT policies:
                    if policytype in ("NATPreRules", "NATPostRules"):
                        for src_elem in policy_entry.findall('./source-translation/translated-address'):
                            addresses_and_groups_in_use.add(src_elem.text)
                        for src_elem in policy_entry.findall('./source-translation/dynamic-ip-and-port/translated-address/member'):
                            addresses_and_groups_in_use.add(src_elem.text)
                        for src_elem in policy_entry.findall('./source-translation/static-ip/translated-address'):
                            addresses_and_groups_in_use.add(src_elem.text)

                        for dest_elem in policy_entry.findall('./destination-translation/translated-address'):
                            addresses_and_groups_in_use.add(dest_elem.text)
                        for dest_elem in policy_entry.findall('./destination-translation/dynamic-ip-and-port/translated-address/member'):
                            addresses_and_groups_in_use.add(dest_elem.text)
                        for dest_elem in policy_entry.findall('./destination-translation/static-ip/translated-address'):
                            addresses_and_groups_in_use.add(dest_elem.text)

        unused_addresses = sorted(set(addresses.keys()) - addresses_and_groups_in_use)
        for unused_address in unused_addresses:
            text = f"Device Group {device_group}'s Address {unused_address} is not in use for any policies or address groups"
            badentries.append(BadEntry(data=[addresses[unused_address]], text=text, device_group=device_group, entry_type='Addresses'))

    return badentries

@register_policy_validator("UnusedAddressGroups", "AddressGroup objects that aren't in use")
def find_unused_addressgroups(profilepackage):
    device_groups = profilepackage.device_groups
    devicegroup_objects = profilepackage.devicegroup_objects
    pan_config = profilepackage.pan_config

    badentries = []

    print ("*"*80)
    print ("Checking for unused Address Group objects")

    for i, device_group in enumerate(device_groups):
        print (f"({i+1}/{len(device_groups)}) Checking {device_group}'s Address Group objects")
        addressgroups = {entry.get('name'):entry for entry in devicegroup_objects[device_group]['AddressGroups']}

        # An address or group can be used by any child device group's Address group or policy. Need to check all of them.
        addresses_and_groups_in_use = set()
        child_dgs = devicegroup_objects[device_group]['all_child_device_groups']
        for child_dg in child_dgs:
            # First check all child Address Groups
            for address_group in devicegroup_objects[child_dg]['AddressGroups']:
                for address_group_elem in address_group.findall('./static/member'):
                    addresses_and_groups_in_use.add(address_group_elem.text)
            # Then check all of the policies. As a note, policies use a mix of addresses and address groups
            for policytype in pan_config.SUPPORTED_POLICY_TYPES:
                policies = devicegroup_objects[child_dg][policytype]
                for policy_entry in policies:
                    for src_elem in policy_entry.findall('./source/member'):
                        addresses_and_groups_in_use.add (src_elem.text)
                    for dest_elem in policy_entry.findall('./destination/member'):
                        addresses_and_groups_in_use.add(dest_elem.text)
                    # Special fields only in NAT policies:
                    if policytype in ("NATPreRules", "NATPostRules"):
                        for src_elem in policy_entry.findall('./source-translation/translated-address'):
                            addresses_and_groups_in_use.add(src_elem.text)
                        for src_elem in policy_entry.findall('./source-translation/dynamic-ip-and-port/translated-address/member'):
                            addresses_and_groups_in_use.add(src_elem.text)
                        for src_elem in policy_entry.findall('./source-translation/static-ip/translated-address'):
                            addresses_and_groups_in_use.add(src_elem.text)

                        for dest_elem in policy_entry.findall('./destination-translation/translated-address'):
                            addresses_and_groups_in_use.add(dest_elem.text)
                        for dest_elem in policy_entry.findall('./destination-translation/dynamic-ip-and-port/translated-address/member'):
                            addresses_and_groups_in_use.add(dest_elem.text)
                        for dest_elem in policy_entry.findall('./destination-translation/static-ip/translated-address'):
                            addresses_and_groups_in_use.add(dest_elem.text)

        unused_addressgroups = sorted((addressgroups.keys()) - addresses_and_groups_in_use)
        for unused_addressgroup in unused_addressgroups:
            text = f"Device Group {device_group}'s Address Group {unused_addressgroup} is not in use for any policies or address groups"
            badentries.append(BadEntry(data=[addressgroups[unused_addressgroup]], text=text, device_group=device_group, entry_type='AddressGroups'))

    return badentries