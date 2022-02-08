from palo_alto_firewall_analyzer.core import register_policy_fixer, get_policy_validators
from palo_alto_firewall_analyzer import pan_api

def consolidate_service_like_objects(profilepackage, object_friendly_type, validator_function):
    panorama = profilepackage.panorama
    api_key = profilepackage.api_key
    pan_config = profilepackage.pan_config
    version = pan_config.get_major_version()

    print ("*"*80)
    print (f"Checking for unused {object_friendly_type} objects to consolidate")

    badentries_needing_consolidation = validator_function(profilepackage)

    if not badentries_needing_consolidation:
        return badentries_needing_consolidation

    print(f"Replacing the contents of {len(badentries_needing_consolidation)} Objects and Policies" )
    for badentry in badentries_needing_consolidation:
        object_policy_entry, object_policy_dict = badentry.data
        object_policy_dg = badentry.device_group
        object_policy_type = badentry.entry_type

        if object_policy_type in pan_config.SUPPORTED_OBJECT_TYPES:
            pan_api.update_devicegroup_object(panorama, version, api_key, object_policy_dict, object_policy_type, object_policy_dg)
        elif object_policy_type in pan_config.SUPPORTED_POLICY_TYPES:
            pan_api.update_devicegroup_policy(panorama, version, api_key, object_policy_dict, object_policy_type, object_policy_dg)
    pan_api.validate_commit(panorama, api_key)
    print ("Replacement complete. Please commit in the firewall.")
    return badentries_needing_consolidation

@register_policy_fixer("ConsolidateServices", "Consolidate use of equivalent Service objects so only one object is used")
def delete_unused_addresses(profilepackage):
    object_friendly_type = "Service"
    _, _, validator_function = get_policy_validators()['FindConsolidatableServices']
    return consolidate_service_like_objects(profilepackage, object_friendly_type, validator_function)


@register_policy_fixer("ConsolidateServiceGroups", "Consolidate use of equivalent ServiceGroup objects so only one object is used")
def delete_unused_addressgroups(profilepackage):
    object_friendly_type = "Service Group"
    _, _, validator_function = get_policy_validators()['FindConsolidatableServiceGroups']
    return consolidate_service_like_objects(profilepackage, object_friendly_type, validator_function)
