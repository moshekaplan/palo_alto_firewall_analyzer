import collections

from palo_alto_firewall_analyzer.core import BadEntry, register_policy_validator, get_policy_validators, xml_object_to_dict


def find_objects_needing_consolidation(equivalent_objects):
    # Takes as input the results from EquivalentServices
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
    services_to_counts = collections.Counter()
    for child_dg in devicegroup_objects[device_group]['all_child_device_groups']:
        # First check all child Services Groups
        for servicegroup in devicegroup_objects[child_dg]['ServiceGroups']:
            for member_element in servicegroup.findall('./members/member'):
                services_to_counts[member_element.text] += 1
        # Then check all of the policies
        for policytype in pan_config.SUPPORTED_POLICY_TYPES:
            for policy_entry in devicegroup_objects[child_dg][policytype]:
                if policytype in ("NATPreRules", "NATPostRules"):
                    for service_element in policy_entry.findall('./service'):
                        services_to_counts[service_element.text] += 1
                else:
                    for service_child_element in policy_entry.findall('./service/'):
                        services_to_counts[service_child_element.text] += 1

    # Then determine to determine which object will be used, create a mapping of old names to new names
    old_services_to_replacements = {}
    for services_to_consolidate in objects_to_consolidate:
        most_common_service = max(services_to_consolidate, key=lambda x: services_to_counts[x])
        for service in services_to_consolidate:
            if service != most_common_service:
                old_services_to_replacements[service] = most_common_service
    return old_services_to_replacements

def find_objects_policies_needing_replacement(pan_config, devicegroup_objects, device_group, service_to_replacement):
    services_to_replace = set(service_to_replacement.keys())
    servicegroups_needing_replacement = []
    policies_needing_replacement = []

    for child_dg in devicegroup_objects[device_group]['all_child_device_groups']:
        # First check all child Services Groups
        for servicegroup in devicegroup_objects[child_dg]['ServiceGroups']:
            for member_element in servicegroup.findall('./members/member'):
                if member_element.text in services_to_replace:
                    servicegroups_needing_replacement += [(child_dg, 'ServiceGroups', servicegroup)]
                    break
        # Then check all of the policies
        for policytype in pan_config.SUPPORTED_POLICY_TYPES:
            for policy_entry in devicegroup_objects[child_dg][policytype]:
                if policytype in ("NATPreRules", "NATPostRules"):
                    for service_element in policy_entry.findall('./service'):
                        if service_element.text in services_to_replace:
                            policies_needing_replacement += [(child_dg, policytype, policy_entry)]
                            break
                else:
                    for service_child_element in policy_entry.findall('./service/'):
                        if service_child_element.text in services_to_replace:
                            policies_needing_replacement += [(child_dg, policytype, policy_entry)]
                            break
    return servicegroups_needing_replacement, policies_needing_replacement



def consolidate_service_like_objects(profilepackage, object_type, object_friendly_type, validator_function):
    panorama = profilepackage.panorama
    pan_config = profilepackage.pan_config
    devicegroup_objects = profilepackage.devicegroup_objects

    print ("*"*80)
    print (f"Checking for unused {object_friendly_type} objects to consolidate")

    # Objects will only be consolidated at the same device group level, to avoid potential scope issues
    equivalent_objects = validator_function(profilepackage)
    dg_to_objects_to_consolidate = find_objects_needing_consolidation(equivalent_objects)

    if not dg_to_objects_to_consolidate:
        print (f"There were no {object_friendly_type} to consolidate")
        return dg_to_objects_to_consolidate

    badentries = []
    for device_group, objects_to_consolidate in dg_to_objects_to_consolidate.items():
        # Determine which object is most commonly-used to minimize the amount of changes that will be needed
        service_to_replacement = find_replacement_objects(pan_config, devicegroup_objects, device_group, objects_to_consolidate)
        # Get the list of objects that will need to be updated:
        servicegroups_needing_replacement, policies_needing_replacement = find_objects_policies_needing_replacement(pan_config, devicegroup_objects, device_group, service_to_replacement)

        # Now that we know which objects need replacements, we can iterate through
        # and make those replacements!
        # First replace the contents of servicegroups
        for object_dg, object_type, object_entry in servicegroups_needing_replacement:
            object_policy_dict = xml_object_to_dict(object_entry)['entry']
            new_services = []
            replacements_made = {}
            for member in object_policy_dict['members']['member']:
                if member in new_services:
                    # Member is already present, nothing to do
                    continue
                elif member not in service_to_replacement:
                    # Member is not present and doesn't need to be replaced, so keep it as is:
                    new_services.append(member)
                elif member in service_to_replacement and service_to_replacement[member] not in new_services:
                    # Member needs to be replaced, and replacement is not already present, so add it:
                    new_services.append(service_to_replacement[member])
                    replacements_made[member] = service_to_replacement[member]
                else:
                    # Member needs to be replaced, but replacement is already present, so nothing to do:
                    continue
            assert object_policy_dict['members']['member'] != new_services
            object_policy_dict['members']['member'] = new_services
            text = f"Replace the following Service members in {object_dg}'s {object_type} {object_entry.get('name')}: {sorted([k + ' with ' + v for k, v in replacements_made.items()])}"
            badentries.append(BadEntry(data=[object_entry, object_policy_dict], text=text, device_group=object_dg, entry_type=object_type))

        # Then replace the contents of policies
        for policy_dg, policy_type, policy_entry in policies_needing_replacement:
            object_policy_dict = xml_object_to_dict(policy_entry)['entry']
            replacements_made = {}
            if policy_type in ("NATPreRules", "NATPostRules"):
                # NAT rules are limited to a single service
                member_to_replace = object_policy_dict['service']
                replacements_made[member_to_replace] = service_to_replacement[member_to_replace]
                object_policy_dict['service'] = service_to_replacement[member_to_replace]
            # If it's a policy with only one member, it'll be parsed as a string, not a list
            elif isinstance(object_policy_dict['service']['member'], str):
                member_to_replace = object_policy_dict['service']['member']
                replacements_made[member_to_replace] = service_to_replacement[member_to_replace]
                object_policy_dict['service']['member'] = service_to_replacement[member_to_replace]
            else:
                new_services = []
                for member in object_policy_dict['service']['member']:
                    if member in new_services:
                        # Member is already present, nothing to do
                        continue
                    elif member not in service_to_replacement:
                        # Member is not present and doesn't need to be replaced, so keep it as is:
                        new_services.append(member)
                    elif member in service_to_replacement and service_to_replacement[member] not in new_services:
                        # Member needs to be replaced, and replacement is not already present, so add it:
                        replacements_made[member_to_replace] = service_to_replacement[member_to_replace]
                        new_services.append(service_to_replacement[member])
                    else:
                        # Member needs to be replaced, but replacement is already present, so nothing to do:
                        continue
                assert object_policy_dict['service']['member'] != new_services
                object_policy_dict['service']['member'] = new_services
            text = f"Replace the following Service members in {policy_dg}'s {policy_type} {policy_entry.get('name')}: {sorted([k + ' with ' + v for k, v in replacements_made.items()])}"
            badentries.append(BadEntry(data=[policy_entry, object_policy_dict], text=text, device_group=policy_dg, entry_type=policy_type))
    return badentries

@register_policy_validator("FindConsolidatableServices", "Consolidate use of equivalent Service objects so only one object is used")
def find_consolidatable_services(profilepackage):
    object_type = "Services"
    object_friendly_type = "Service"
    _, _, validator_function = get_policy_validators()['EquivalentServices']
    return consolidate_service_like_objects(profilepackage, object_type, object_friendly_type, validator_function)

@register_policy_validator("FindConsolidatableServiceGroups", "Consolidate use of equivalent ServiceGroup objects so only one object is used")
def find_consolidatable_servicesgroups(profilepackage):
    object_type = "ServiceGroups"
    object_friendly_type = "Service Group"
    _, _, validator_function = get_policy_validators()['EquivalentServiceGroups']
    return consolidate_service_like_objects(profilepackage, object_type, object_friendly_type, validator_function)
