import logging

from palo_alto_firewall_analyzer.core import register_policy_fixer, get_policy_validators
from palo_alto_firewall_analyzer import pan_api

logger = logging.getLogger(__name__)

def consolidate_service_like_objects(profilepackage, object_friendly_type, validator_function):
    panorama = profilepackage.settings.get("Panorama")
    api_key = profilepackage.api_key
    pan_config = profilepackage.pan_config
    version = pan_config.get_major_version()

    logger.info("*"*80)
    logger.info(f"Checking for unused {object_friendly_type} objects to consolidate")

    badentries_needing_consolidation = validator_function(profilepackage)

    if not badentries_needing_consolidation:
        return badentries_needing_consolidation

    logger.info(f"Replacing the contents of {len(badentries_needing_consolidation)} Objects and Policies" )
    for badentry in badentries_needing_consolidation:
        object_policy_entry, object_policy_dict = badentry.data
        object_policy_dg = badentry.device_group
        object_policy_type = badentry.entry_type
        if object_policy_type in pan_config.SUPPORTED_OBJECT_TYPES:
            pan_api.update_devicegroup_object(panorama, version, api_key, object_policy_dict, object_policy_type, object_policy_dg)
        elif object_policy_type in pan_config.SUPPORTED_POLICY_TYPES:
            pan_api.update_devicegroup_policy(panorama, version, api_key, object_policy_dict, object_policy_type, object_policy_dg)
    pan_api.validate_commit(panorama, api_key)
    logger.info("Replacement complete. Please commit in the firewall.")
    return badentries_needing_consolidation

@register_policy_fixer("ConsolidateServices", "Consolidate use of equivalent Service objects so only one object is used")
def consolidate_services(profilepackage):
    object_friendly_type = "Service"
    _, _, validator_function = get_policy_validators()['FindConsolidatableServices']
    return consolidate_service_like_objects(profilepackage, object_friendly_type, validator_function)


@register_policy_fixer("ConsolidateServiceGroups", "Consolidate use of equivalent ServiceGroup objects so only one object is used")
def consolidate_servicegroups(profilepackage):
    object_friendly_type = "Service Group"
    _, _, validator_function = get_policy_validators()['FindConsolidatableServiceGroups']
    return consolidate_service_like_objects(profilepackage, object_friendly_type, validator_function)


@register_policy_fixer("ConsolidateAddresses", "Consolidate use of equivalent Address objects so only one object is used")
def consolidate_addresses(profilepackage):
    object_friendly_type = "Address"
    _, _, validator_function = get_policy_validators()['FindConsolidatableAddresses']
    return consolidate_service_like_objects(profilepackage, object_friendly_type, validator_function)


@register_policy_fixer("ConsolidateAddressGroups", "Consolidate use of equivalent AddressGroup objects so only one object is used")
def consolidate_addressgroups(profilepackage):
    object_friendly_type = "Address Group"
    _, _, validator_function = get_policy_validators()['FindConsolidatableAddressGroups']
    return consolidate_service_like_objects(profilepackage, object_friendly_type, validator_function)