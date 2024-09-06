import logging

from palo_alto_firewall_analyzer.core import BadEntry, cached_dns_lookup, register_policy_validator, get_policy_validators
from palo_alto_firewall_analyzer.scripts.pan_details import parsed_details

logger = logging.getLogger(__name__)

@register_policy_validator("BadHostname", "Address contains a hostname that doesn't resolve")
def find_badhostname(profilepackage):
    device_groups = profilepackage.device_groups
    devicegroup_objects = profilepackage.devicegroup_objects
    ignored_dns_prefixes = tuple([prefix.lower() for prefix in profilepackage.settings.get('Ignored DNS Prefixes','').split(',')])
 
    badentries = []
    count_checks = 0
    
    logger.info("*" * 80)
    logger.info("Checking for non-resolving hostnames")

    bad_address_objects = set()
    for i, device_group in enumerate(device_groups):
        logger.info(f"({i + 1}/{len(device_groups)}) Checking {device_group}'s Addresses")
        for entry in devicegroup_objects[device_group]['Addresses']:
            entry_name = entry.get('name')
            for fqdn_node in entry.findall('fqdn'):
                count_checks+=1
                fqdn_text = fqdn_node.text.lower()
                if any(fqdn_text.startswith(ignored_prefix) for ignored_prefix in ignored_dns_prefixes):
                    continue
                ip = cached_dns_lookup(fqdn_text)
                if ip is None:
                    bad_address_objects.add(entry_name)                    
                    text = f"Device Group {device_group}'s address '{entry_name}' uses the following FQDN which doesn't resolve: '{fqdn_text}'"
                    detail={
                        "device_group":device_group,
                        "entry_name":entry_name,
                        "entry_type":'Addresses',
                        "fqdn_text":fqdn_text
                        }
                    badentries.append(
                        BadEntry(data=entry, text=text, device_group=device_group, entry_type='Addresses', Detail=parsed_details(detail)))
                
    return badentries,count_checks

@register_policy_validator("BadHostnameUsage", "AddressGroups and Security Rules using Address objects which don't resolve")
def find_badhostnameusage(profilepackage):
    device_groups = profilepackage.device_groups
    devicegroup_objects = profilepackage.devicegroup_objects
    devicegroup_exclusive_objects = profilepackage.devicegroup_exclusive_objects

    _, _, validator_function = get_policy_validators()['BadHostname']

    bad_hostname_results,count_checks = validator_function(profilepackage)
    bad_address_objects = set()
    for entry in bad_hostname_results:
        bad_address_objects.add(entry.data.get('name'))
        
    
    badentries = []
    for i, device_group in enumerate(device_groups):
        logger.info(f"({i + 1}/{len(device_groups)}) Checking {device_group}'s Address Groups")
        for entry in devicegroup_objects[device_group]['AddressGroups']:
            count_checks+=1
            address_group_members = []
            for ag_member in entry.findall('./static/member'):
                address_group_members.append(ag_member.text)
            bad_members = bad_address_objects & set(address_group_members)
            if bad_members:
                count_checks+=1
                text = f"Device Group {device_group}'s Address Group '{entry.get('name')}' uses the following address objects which don't resolve: {sorted(bad_members)}"
                detail={
                    "device_group":device_group,
                    "entry_type":'AddressGroups', 
                    "entry_name":entry.get('names'),
                    "extra":sorted(bad_members)
                    }
                badentries.append(
                    BadEntry(data=entry, text=text, device_group=device_group, entry_type='AddressGroups',Detail=parsed_details(detail)))

    for i, device_group in enumerate(device_groups):
        for ruletype in ('SecurityPreRules', 'SecurityPostRules'):
            rules = devicegroup_exclusive_objects[device_group][ruletype]
            logger.info(f"({i + 1}/{len(device_groups)}) Checking {device_group}'s {ruletype}")

            for entry in rules:
                # Disabled rules can be ignored
                if entry.find("./disabled") is not None and entry.find("./disabled").text == "yes":
                    continue

                rule_name = entry.get('name')
                source_members = set([sm.text for sm in entry.findall('./source/member')])
                dest_members = set([dm.text for dm in entry.findall('./destination/member')])

                for members, direction in [(source_members, 'Source'), (dest_members, 'Dest')]:
                    count_checks+=1
                    bad_members = bad_address_objects & members
                    if bad_members:
                        text = f"Device Group {device_group}'s {ruletype} '{rule_name}' {direction} contain the following address objects which don't resolve: {sorted(bad_members)}"
                        detail={
                            "device_group":device_group,
                            "entry_type":ruletype,
                            "rule_type":ruletype,
                            "rule_name":rule_name,
                            "direction":direction,
                            "extra":sorted(bad_members)}
                        badentries.append(
                            BadEntry(data=entry, text=text, device_group=device_group, entry_type=ruletype,Detail=parsed_details(detail)))
    return badentries, count_checks
