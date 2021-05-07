import collections

from palo_alto_firewall_analyzer.core import BadEntry, get_single_ip_from_address, register_policy_validator, xml_object_to_dict
from palo_alto_firewall_analyzer.pan_api_helpers import get_firewall_zone

def get_underlying_address_objects(address_group_name, name_to_address_groups, name_to_addresses):
    """
    address_group_entry: An AddressGroup object
    name_to_address_groups: Dict of name -> AddressGroup objects
    name_to_addresses: Dict of name -> Address objects
    Return: A list of Address objects
    """
    addresses = []
    for member_name in name_to_address_groups[address_group_name]:
        if member_name in name_to_address_groups:
            addresses += get_underlying_address_objects(member_name, name_to_address_groups, name_to_addresses)
        elif member_name in name_to_addresses:
            addresses += [member_name]
        else:
            raise Exception(f"Unresolved member name '{member_name}'. This shouldn't be possible!")
    return addresses


@register_policy_validator("MissingZones", "Rule is missing a Zone!")
def find_missing_zones(profilepackage):
    device_groups = profilepackage.device_groups
    devicegroup_objects = profilepackage.devicegroup_objects
    devicegroup_exclusive_objects = profilepackage.devicegroup_exclusive_objects
    device_group_hierarchy_parent = profilepackage.device_group_hierarchy_parent
    api_key = profilepackage.api_key

    badentries = []
    print ("*"*80)
    print ("Checking for Missing Zones")
    for i, device_group in enumerate(device_groups):
        firewalls = devicegroup_objects[device_group]['all_active_child_firewalls']

        addresses = {entry.get('name'):entry for entry in devicegroup_objects[device_group]['Addresses']}
        address_groups = {entry.get('name'):entry for entry in devicegroup_objects[device_group]['AddressGroups']}

        # Address and Address Group objects can be inherited from parent device groups, so we need data from them too
        parent_dgs = []
        current_dg = device_group_hierarchy_parent.get(device_group)
        while current_dg:
            parent_dgs.append(current_dg)
            current_dg = device_group_hierarchy_parent.get(current_dg)

        for parent_dg in parent_dgs:
            for address_entry in devicegroup_objects[parent_dg]['Addresses']:
                addresses[address_entry.get('name')] = address_entry
            for address_group_entry in devicegroup_objects[parent_dg]['AddressGroups']:
                address_group_members = [elem.text for elem in address_group_entry.findall('./static/member')]
                address_groups[address_group_entry.get('name')] = address_group_members

        for ruletype in ('SecurityPreRules', 'SecurityPostRules'):
            rules = devicegroup_exclusive_objects[device_group][ruletype]
            print (f"({i+1}/{len(device_groups)}) Checking {device_group}'s {ruletype}")

            total_entries = len(rules)
            for j, entry in enumerate(rules):
                print (f'({j+1}/{total_entries}) {entry.get("name")}')
                # Disabled rules can be ignored
                if entry.find("./disabled") is not None and entry.find("./disabled").text == "yes":
                    continue

                rule_name = entry.get('name')
                src_zones = sorted([elem.text for elem in entry.findall('./from/member')])
                src_members = sorted([elem.text for elem in entry.findall('./source/member')])
                dest_zones = sorted([elem.text for elem in entry.findall('./to/member')])
                dest_members = sorted([elem.text for elem in entry.findall('./destination/member')])

                # Analyze the rules for bad/missing zones
                for members, zones, zonetype in [(src_members, src_zones, 'Source'), (dest_members, dest_zones, 'Dest')]:
                    # Note: Members can be an Address or Address Group
                    ips = []
                    for member_name in members:
                        if member_name in address_groups:
                            all_contained_address_names = get_underlying_address_objects(member_name, address_groups, addresses)
                        elif member_name in addresses:
                            all_contained_address_names = [member_name]

                        for address_name in all_contained_address_names:
                            # Idea: Grab a single IP address from each member. Looking up every single contained IP does not scale.
                            address_entry = addresses[address_name]
                            ip = get_single_ip_from_address(address_entry)
                            if ip:
                                ips += [ip]

                    calculated_zones_to_ips = collections.defaultdict(list)
                    for firewall in firewalls:
                        for ip in ips:
                            try:
                                zone = get_firewall_zone(firewall, api_key, ip)
                                calculated_zones_to_ips[zone].append(ip)
                            except:
                                pass

                    # Missing a zone, so the rule won't work properly:
                    missing_zones = sorted(set(calculated_zones_to_ips) - set(zones))
                    if 'any' not in zones and missing_zones:
                        missing_template = "IPs {ips} require {zonetype} zone '{zone}'."
                        missing_text = " ".join([missing_template.format(zone=zone, ips=calculated_zones_to_ips[zone], zonetype=zonetype) for zone in missing_zones])
                        text = f"Device Group '{device_group}'s {ruletype} '{rule_name}' uses {zonetype} zones {zones}. " + missing_text
                        print (text)
                        badentries.append(BadEntry(data=entry, text=text, device_group=device_group, entry_type=ruletype))
    return badentries

@register_policy_validator("ExtraZones", "Rule has an extra Zone!")
def find_extra_zones(profilepackage):
    device_groups = profilepackage.device_groups
    devicegroup_objects = profilepackage.devicegroup_objects
    devicegroup_exclusive_objects = profilepackage.devicegroup_exclusive_objects
    api_key = profilepackage.api_key
    device_group_hierarchy_parent = profilepackage.device_group_hierarchy_parent

    badentries = []
    print ("*"*80)
    print ("Checking for Extra Zones")
    for i, device_group in enumerate(device_groups):
        firewalls = devicegroup_objects[device_group]['all_active_child_firewalls']

        addresses = {entry.get('name'):entry for entry in devicegroup_objects[device_group]['Addresses']}
        address_groups = {entry.get('name'):entry for entry in devicegroup_objects[device_group]['AddressGroups']}

        # Address and Address Group objects can be inherited from parent device groups, so we need data from them too
        parent_dgs = []
        current_dg = device_group_hierarchy_parent.get(device_group)
        while current_dg:
            parent_dgs.append(current_dg)
            current_dg = device_group_hierarchy_parent.get(current_dg)

        for parent_dg in parent_dgs:
            for address_entry in devicegroup_objects[parent_dg]['Addresses']:
                addresses[address_entry.get('name')] = address_entry
            for address_group_entry in devicegroup_objects[parent_dg]['AddressGroups']:
                address_group_members = [elem.text for elem in address_group_entry.findall('./static/member')]
                address_groups[address_group_entry.get('name')] = address_group_members

        for ruletype in ('SecurityPreRules', 'SecurityPostRules'):
            rules = devicegroup_exclusive_objects[device_group][ruletype]
            print (f"({i+1}/{len(device_groups)}) Checking {device_group}'s {ruletype}")

            total_entries = len(rules)
            for j, entry in enumerate(rules):
                print (f'({j+1}/{total_entries}) {entry.get("name")}')
                # Disabled rules can be ignored
                if entry.find("./disabled") is not None and entry.find("./disabled").text == "yes":
                    continue

                rule_name = entry.get('name')
                src_zones = sorted([elem.text for elem in entry.findall('./from/member')])
                src_members = sorted([elem.text for elem in entry.findall('./source/member')])
                dest_zones = sorted([elem.text for elem in entry.findall('./to/member')])
                dest_members = sorted([elem.text for elem in entry.findall('./destination/member')])

                # Analyze the rules for bad/missing zones
                for members, zones, zonetype in [(src_members, src_zones, 'Source'), (dest_members, dest_zones, 'Dest')]:
                    ips = []
                    # Note: Members can be an Address or Address Group
                    # Looking up the zone for every single IP does not scale - there could be many /16's
                    # However, grabbing only a single IP address from each member can result in false positives
                    # if a single Address object contains a large enough subnet that it spans multiple zones.
                    # To avoid false positives, we'll only report an issue if all of a policy's members
                    # are resolvable to a single IP.

                    missing_ips = False
                    for member_name in members:
                        if member_name == 'any':
                            missing_ips = True
                            break

                        if member_name in address_groups:
                            all_contained_address_names = get_underlying_address_objects(member_name, address_groups, addresses)
                        elif member_name in addresses:
                            all_contained_address_names = [member_name]
                        else:
                            raise Exception("Unable to resolve member '%s'. This should be impossible! Please report the bug" % member_name)

                        for address_name in all_contained_address_names:
                            # Only look up IPs if there is a single entry in the Address Object.
                            address_entry = addresses[address_name]
                            address_dict = xml_object_to_dict(address_entry)['entry']
                            if "fqdn" in address_dict or ("ip-netmask" in address_dict and ("/" not in address_dict['ip-netmask'] or "/32" in address_dict['ip-netmask'])):
                                ip = get_single_ip_from_address(address_entry)
                                if ip:
                                    ips += [ip]
                            else:
                                missing_ips = True
                                break
                        if missing_ips:
                            break
                    if missing_ips:
                        continue

                    calculated_zones_to_ips = collections.defaultdict(list)
                    for firewall in firewalls:
                        for ip in ips:
                            try:
                                zone = get_firewall_zone(firewall, api_key, ip)
                                calculated_zones_to_ips[zone].append(ip)
                            except:
                                pass

                    extra_zones = sorted(set(zones) - set(calculated_zones_to_ips))
                    if extra_zones:
                        text = f"Device Group '{device_group}'s {ruletype} '{rule_name}' uses {zonetype} zones {zones}. The {zonetype} zones should be {sorted(calculated_zones_to_ips)}. The following {zonetype} zones are not needed: {extra_zones}"
                        print (text)
                        badentries.append( BadEntry(data=entry, text=text, device_group=device_group, entry_type=ruletype) )
    return badentries

@register_policy_validator("ExtraRules", "Rule has a single Source/Dest Zone! Rule is not needed!")
def find_extra_rules(profilepackage):
    device_groups = profilepackage.device_groups
    devicegroup_objects = profilepackage.devicegroup_objects
    devicegroup_exclusive_objects = profilepackage.devicegroup_exclusive_objects
    api_key = profilepackage.api_key
    device_group_hierarchy_parent = profilepackage.device_group_hierarchy_parent

    badentries = []
    print ("*"*80)
    print ("Checking for Extra rules")
    for i, device_group in enumerate(device_groups):
        firewalls = devicegroup_objects[device_group]['all_active_child_firewalls']

        addresses = {entry.get('name'):entry for entry in devicegroup_objects[device_group]['Addresses']}
        address_groups = {entry.get('name'):entry for entry in devicegroup_objects[device_group]['AddressGroups']}

        # Address and Address Group objects can be inherited from parent device groups, so we need data from them too
        parent_dgs = []
        current_dg = device_group_hierarchy_parent.get(device_group)
        while current_dg:
            parent_dgs.append(current_dg)
            current_dg = device_group_hierarchy_parent.get(current_dg)

        for parent_dg in parent_dgs:
            for address_entry in devicegroup_objects[parent_dg]['Addresses']:
                addresses[address_entry.get('name')] = address_entry
            for address_group_entry in devicegroup_objects[parent_dg]['AddressGroups']:
                address_group_members = [elem.text for elem in address_group_entry.findall('./static/member')]
                address_groups[address_group_entry.get('name')] = address_group_members

        for ruletype in ('SecurityPreRules', 'SecurityPostRules'):
            rules = devicegroup_exclusive_objects[device_group][ruletype]
            print (f"({i+1}/{len(device_groups)}) Checking {device_group}'s {ruletype}")

            total_entries = len(rules)
            for j, entry in enumerate(rules):
                print (f'({j+1}/{total_entries}) {entry.get("name")}')
                # Disabled rules can be ignored
                if entry.find("./disabled") is not None and entry.find("./disabled").text == "yes":
                    continue

                rule_name = entry.get('name')
                src_members = sorted([elem.text for elem in entry.findall('./source/member')])
                dest_members = sorted([elem.text for elem in entry.findall('./destination/member')])

                # Analyze the rules for rules where if there is one source/dest zone and both are the same,
                # so the rule isn't needed.
                # Note: Members can be an Address or Address Group Looking up the zones for
                # every single IP does not scale - there could be many /16's However, grabbing only a single IP
                # address from each member can result in false positives if a single Address object contains a large
                # enough subnet that it spans multiple zones. To avoid false positives, we'll only report an issue if
                # all of a policy's members are resolvable to a single IP.

                missing_ips = False
                ips = {'Source': [], 'Dest': []}
                for members, zonetype in [(src_members, 'Source'), (dest_members, 'Dest')]:
                    for member_name in members:
                        if member_name == 'any':
                            missing_ips = True
                            break

                        if member_name in address_groups:
                            all_contained_address_names = get_underlying_address_objects(member_name, address_groups, addresses)
                        elif member_name in addresses:
                            all_contained_address_names = [member_name]

                        for address_name in all_contained_address_names:
                            # Only look up IPs if there is a single entry in the Address Object.
                            address_entry = addresses[address_name]
                            address_dict = xml_object_to_dict(address_entry)['entry']
                            if "fqdn" in address_dict or ("ip-netmask" in address_dict and ("/" not in address_dict['ip-netmask'] or "/32" in address_dict['ip-netmask'])):
                                ip = get_single_ip_from_address(address_entry)
                                if ip:
                                    ips[zonetype] += [ip]
                            else:
                                missing_ips = True
                                break
                        if missing_ips:
                            break
                    if missing_ips:
                        break
                if missing_ips:
                    continue

                calculated_src_zones = set()
                for firewall in firewalls:
                    for ip in ips['Source']:
                        try:
                            zone = get_firewall_zone(firewall, api_key, ip)
                            calculated_src_zones.add(zone)
                        except:
                            pass

                calculated_dest_zones = set()
                for firewall in firewalls:
                    for ip in ips['Dest']:
                        try:
                            zone = get_firewall_zone(firewall, api_key, ip)
                            calculated_dest_zones.add(zone)
                        except:
                            pass

                if len(calculated_src_zones) == 1 and calculated_src_zones == calculated_dest_zones:
                    text = f"Device Group '{device_group}'s {ruletype} '{rule_name}' was calculated to only need the same source and dest zone of '{list(calculated_dest_zones)[0]}'."
                    print (text)
                    badentries.append( BadEntry(data=entry, text=text, device_group=device_group, entry_type=ruletype) )
    return badentries
