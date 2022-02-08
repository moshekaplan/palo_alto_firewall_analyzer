import collections
import ipaddress

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

def get_zone_for_source_member(firewall, api_key, member_name, address_groups, addresses, regions):
    # Note: Members can be an IP, Subnet, IP Range, Address, Address Group, or Region (in that order of resolution priority).
    # Looking up the zone for every single IP in a subnet does not scale - there could be a /16's,
    # so instead we'll only get the zone for the first object in the address group/Region/Subnet/IP Range
    # and return a bool as to whether or not the result is complete
    # Returns: list of zones as List[str], True if it's complete

    if member_name == 'any':
        return [], False

    try:
        if member_name in address_groups:
            all_contained_address_names = get_underlying_address_objects(member_name, address_groups, addresses)
            if len(all_contained_address_names) == 0:
                return [], True
            else:
                zones = []
                is_complete = True
                for address_name in all_contained_address_names:
                    # Only look up IPs if there is a single entry in the Address Object.
                    address_entry = addresses[address_name]
                    address_dict = xml_object_to_dict(address_entry)['entry']
                    if "fqdn" in address_dict or ("ip-netmask" in address_dict and ("/" not in address_dict['ip-netmask'] or "/32" in address_dict['ip-netmask'])):
                        ip = get_single_ip_from_address(address_entry)
                        if ip:
                            zones += [get_firewall_zone(firewall, api_key, ip)]
                    else:
                        is_complete = False
                return zones, is_complete
        elif member_name in addresses:
            zones = []
            is_complete = True
            address_entry = addresses[member_name]
            address_dict = xml_object_to_dict(address_entry)['entry']
            if "fqdn" in address_dict or ("ip-netmask" in address_dict and ("/" not in address_dict['ip-netmask'] or "/32" in address_dict['ip-netmask'])):
                ip = get_single_ip_from_address(address_entry)
                if ip:
                    zones += [get_firewall_zone(firewall, api_key, ip)]
            else:
                is_complete = False
            return zones, is_complete
        else:
            # Entry is an IP, subnet, or range:
            # Attempt to extract an IP
            # Use ipaddress.ip_address and ipaddress.ip_network to validate
            if '-' in member_name:
                start_range, end_range = member_name.split('-')
                ip = start_range
                ipaddress.ip_address(ip)
                is_complete = (start_range == end_range)
            elif '/' in member_name:
                ip, mask = member_name.split('/')
                ipaddress.ip_address(ip)
                is_complete = (mask == 32)
            else:
                ip = member_name
                ipaddress.ip_address(ip)
                is_complete = True
            zones = [get_firewall_zone(firewall, api_key, ip)]
            return zones, is_complete
    except:
        return [], False


@register_policy_validator("MissingZones", "Rule is missing a Zone!")
def find_missing_zones(profilepackage):
    device_groups = profilepackage.device_groups
    devicegroup_objects = profilepackage.devicegroup_objects
    devicegroup_exclusive_objects = profilepackage.devicegroup_exclusive_objects
    device_group_hierarchy_parent = profilepackage.device_group_hierarchy_parent
    api_key = profilepackage.api_key
    no_api = profilepackage.no_api

    if no_api:
        return []

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

                # Analyze each rule for missing zones
                for members, zones, zonetype in [(src_members, src_zones, 'Source'), (dest_members, dest_zones, 'Dest')]:
                    # If the rules allow 'any' zone, it'll work (although it's quite ugly)
                    if 'any' in zones:
                        continue
                    calculated_zones_to_members = collections.defaultdict(list)
                    for member in members:
                        for firewall in firewalls:
                            member_zones, _ = get_zone_for_source_member(firewall, api_key, member, address_groups, addresses, None)
                            # If out calculated zones are missing a zone, that's fine - because that will
                            # be a false negative, not a false positive
                            for member_zone in member_zones:
                                calculated_zones_to_members[member_zone].append(member)
                    # Determine which zones were calculated to be needed, but aren't present:
                    missing_zones = sorted(set(calculated_zones_to_members) - set(zones))

                    if missing_zones:
                        missing_template = "Members {members} require {zonetype} zone '{zone}'."
                        missing_text = " ".join([missing_template.format(zone=zone, members=sorted(set(calculated_zones_to_members[zone])), zonetype=zonetype) for zone in missing_zones])
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
    no_api = profilepackage.no_api

    if no_api:
        return []

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

                # Analyze each rule for extra zones
                for members, zones, zonetype in [(src_members, src_zones, 'Source'), (dest_members, dest_zones, 'Dest')]:
                    # If the rule allows 'any' source address, it's a zone-based rule, not an address-based one
                    if 'any' in members:
                        continue
                    calculated_zones_to_members = collections.defaultdict(list)
                    missing_any = False
                    for member in members:
                        for firewall in firewalls:
                            member_zones, is_complete = get_zone_for_source_member(firewall, api_key, member, address_groups, addresses, None)
                            # If we can't calculate the complete set of expected zones, we can't determine if a zone is extra
                            if not is_complete:
                                missing_any = True
                                break
                            for member_zone in member_zones:
                                calculated_zones_to_members[member_zone].append(member)
                        if missing_any:
                            break

                    extra_zones = sorted(set(zones) - set(calculated_zones_to_members))
                    if extra_zones:
                        text = f"Device Group '{device_group}'s {ruletype} '{rule_name}' uses {zonetype} zones {zones}. The {zonetype} zones should be {sorted(calculated_zones_to_members)}. The following {zonetype} zones are not needed: {extra_zones}"
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
    no_api = profilepackage.no_api

    if no_api:
        return []

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
