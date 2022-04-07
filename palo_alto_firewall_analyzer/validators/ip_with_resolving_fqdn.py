import collections

from palo_alto_firewall_analyzer.core import BadEntry, cached_dns_ex_lookup, register_policy_validator, xml_object_to_dict


@register_policy_validator("IPWithResolvingFQDN", "Address object contains an IP that an existing FQDN resolves to")
def find_IPandFQDN(profilepackage):
    device_groups = profilepackage.device_groups
    pan_config = profilepackage.pan_config

    badentries = []

    print("*" * 80)

    for i, device_group in enumerate(device_groups):
        fqdns = []
        ips = collections.defaultdict(list)
        ips_fqdns_resolve_to = collections.Counter()
        print(f"({i + 1}/{len(device_groups)}) Checking {device_group}'s Addresses")
        for entry in pan_config.get_devicegroup_object('Addresses', device_group):
            entry_name = entry.get('name')
            entry_dict = xml_object_to_dict(entry)
            # If it's a single IP, store it in the dictionary of IPs:
            # Only handle IPv4 for now:
            if 'ip-netmask' in entry_dict['entry'] and '.' in entry_dict['entry']['ip-netmask']:
                if '/' not in entry_dict['entry']['ip-netmask'] or '/32' in entry_dict['entry']['ip-netmask']:
                    ipnetmask_value = entry_dict['entry']['ip-netmask']
                    ip = ipnetmask_value.split('/', 1)[0]
                    ips[ip].append((entry_name, ipnetmask_value, entry))
            # Add FQDNs to the list of FQDNs:
            elif 'fqdn' in entry_dict['entry']:
                fqdn = entry_dict['entry']['fqdn']
                _, _, ipaddrlist = cached_dns_ex_lookup(fqdn)
                for ip in ipaddrlist:
                    fqdns.append((entry_name, fqdn, ip))
                    ips_fqdns_resolve_to[ip] += 1

        # Now that we have the data, we're ready to review the fqdns for what's present in the IPs:
        for fqdn_name, fqdn, ip in fqdns:
            # Skip IPs that have multiple FQDNs on the firewall resolve to them, because it's ambiguous which fqdn to use
            if ip in ips and ips_fqdns_resolve_to[ip] == 1:
                for address_name, ipnetmask_value, address_entry in ips[ip]:
                    text = f"Device Group {device_group}'s address {address_name} with IP {ipnetmask_value} can be replaced with an fqdn of {fqdn}"
                    badentries.append(BadEntry(data=(address_entry, fqdn), text=text, device_group=device_group, entry_type='Addresses'))
    return badentries
