from palo_alto_firewall_analyzer.core import BadEntry, cached_fqdn_lookup, register_policy_validator, get_policy_validators


@register_policy_validator("UnqualifiedFQDN", "Address contains a hostname instead of an FQDN")
def find_badhostname(profilepackage):
    device_groups = profilepackage.device_groups
    devicegroup_objects = profilepackage.devicegroup_objects
    ignored_dns_prefixes = tuple([prefix.lower() for prefix in profilepackage.settings.get('Ignored DNS Prefixes','').split(',')])

    badentries = []

    print("*" * 80)
    print("Checking for FQDN entries that are hostnames and not FQDNs")

    bad_address_objects = set()
    for i, device_group in enumerate(device_groups):
        print(f"({i + 1}/{len(device_groups)}) Checking {device_group}'s Addresses")
        for entry in devicegroup_objects[device_group]['Addresses']:
            entry_name = entry.get('name')
            for fqdn_node in entry.findall('fqdn'):
                fqdn_text = fqdn_node.text.lower()
                if any(fqdn_text.startswith(ignored_prefix) for ignored_prefix in ignored_dns_prefixes):
                    continue
                # FQDN lookups are slow, so only lookup entries that don't have anything resembling a TLD
                if '.' in fqdn_text:
                    continue
                fqdn = cached_fqdn_lookup(fqdn_text)
                if fqdn.lower() != fqdn_text.lower():
                    bad_address_objects.add(entry_name)
                    text = f"Device Group {device_group}'s address '{entry_name}' uses a hostname of '{fqdn_text}' instead of an FQDN of: '{fqdn}'"
                    badentries.append(
                        BadEntry(data=(entry, fqdn), text=text, device_group=device_group, entry_type='Addresses'))
    return badentries
