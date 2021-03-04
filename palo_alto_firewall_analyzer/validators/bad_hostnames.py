from palo_alto_firewall_analyzer.core import BadEntry, cached_dns_lookup, register_policy_validator


@register_policy_validator("BadHostname", "Address contains a hostname that doesn't resolve")
def find_badhostname(profilepackage):
    device_groups = profilepackage.device_groups
    devicegroup_objects = profilepackage.devicegroup_objects
    devicegroup_exclusive_objects = profilepackage.devicegroup_exclusive_objects
    ignored_dns_prefixes = profilepackage.ignored_dns_prefixes

    badentries = []

    print("*" * 80)
    print("Checking for non-existent hostnames")

    bad_fqdns = set()
    for i, device_group in enumerate(device_groups):
        print(f"({i + 1}/{len(device_groups)}) Checking {device_group}'s Addresses")
        for entry in devicegroup_objects[device_group]['Addresses']:
            entry_name = entry.get('name')
            for fqdn_node in entry.findall('fqdn'):
                fqdn_text = fqdn_node.text.lower()
                if any(fqdn_text.startswith(ignored_prefix) for ignored_prefix in ignored_dns_prefixes):
                    continue
                ip = cached_dns_lookup(fqdn_text)
                if ip is None:
                    bad_fqdns.add(entry_name)
                    text = f"Device Group {device_group}'s address '{entry_name}' uses the following FQDN which don't resolve: '{fqdn_text}'"
                    badentries.append(
                        BadEntry(data=entry, text=text, device_group=device_group, entry_type='Addresses'))

    for i, device_group in enumerate(device_groups):
        print(f"({i + 1}/{len(device_groups)}) Checking {device_group}'s Address Groups")
        for entry in devicegroup_objects[device_group]['AddressGroups']:
            address_group_members = []
            for ag_member in entry.findall('./static/member'):
                address_group_members.append(ag_member.text)
            bad_members = bad_fqdns & set(address_group_members)
            if bad_members:
                text = f"Device Group {device_group}'s Address Group '{entry.get('name')}' uses the following FQDNs which don't resolve: {sorted(bad_members)}"
                badentries.append(
                    BadEntry(data=entry, text=text, device_group=device_group, entry_type='AddressGroups'))

    for i, device_group in enumerate(device_groups):
        for ruletype in ('SecurityPreRules', 'SecurityPostRules'):
            rules = devicegroup_exclusive_objects[device_group][ruletype]
            print(f"({i + 1}/{len(device_groups)}) Checking {device_group}'s {ruletype}")

            for entry in rules:
                # Disabled rules can be ignored
                if entry.find("./disabled") is not None and entry.find("./disabled").text == "yes":
                    continue

                rule_name = entry.get('name')
                source_members = set([sm.text for sm in entry.findall('./source/member')])
                dest_members = set([dm.text for dm in entry.findall('./destination/member')])

                for members, direction in [(source_members, 'Source'), (dest_members, 'Dest')]:
                    bad_members = bad_fqdns & members
                    if bad_members:
                        text = f"Device Group {device_group}'s {ruletype} '{rule_name}' {direction} contain the following addresses which don't resolve: {sorted(bad_members)}"
                        badentries.append(
                            BadEntry(data=entry, text=text, device_group=device_group, entry_type=ruletype))
    return badentries
