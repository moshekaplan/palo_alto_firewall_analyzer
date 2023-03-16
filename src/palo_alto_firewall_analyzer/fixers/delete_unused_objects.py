import logging

import requests

from palo_alto_firewall_analyzer.core import register_policy_fixer, get_policy_validators
from palo_alto_firewall_analyzer import pan_api

logger = logging.getLogger(__name__)

def delete_unused_object(profilepackage, object_type, object_friendly_type, validator_function):
    panorama = profilepackage.settings.get("Panorama")
    api_key = profilepackage.api_key
    pan_config = profilepackage.pan_config
    version = pan_config.get_major_version()

    logger.info("*" * 80)
    logger.info(f"Checking for unused {object_friendly_type} objects to delete")

    results_to_delete = validator_function(profilepackage)

    if not results_to_delete:
        logger.info(f"There were no {object_friendly_type} to delete")
        return results_to_delete

    logger.info(f"Deleting {len(results_to_delete)} unused {object_friendly_type} objects now")
    for badentry in results_to_delete:
        device_group = badentry.device_group
        object_name = badentry.data[0].get('name')
        logger.info(f"Deleting {object_name} from {device_group}")
        try:
            pan_api.delete_object(panorama, version, api_key, object_type, object_name, device_group)
        except requests.HTTPError as err:
            logger.info(f"Error deleting {object_name} from {device_group}: {err.response.text}")
    pan_api.validate_commit(panorama, api_key)
    logger.info(f"Deletion of {len(results_to_delete)} unused {object_friendly_type} objects complete. Please commit in the firewall.")
    return results_to_delete


@register_policy_fixer("DeleteUnusedAddresses", "Delete Address objects that aren't in use")
def delete_unused_addresses(profilepackage):
    object_type = "Addresses"
    object_friendly_type = "Address"
    _, _, validator_function = get_policy_validators()['UnusedAddresses']
    return delete_unused_object(profilepackage, object_type, object_friendly_type, validator_function)


@register_policy_fixer("DeleteUnusedAddressGroups", "Delete AddressGroup objects that aren't in use")
def delete_unused_addressgroups(profilepackage):
    object_type = "AddressGroups"
    object_friendly_type = "Address Group"
    _, _, validator_function = get_policy_validators()['UnusedAddressGroups']
    return delete_unused_object(profilepackage, object_type, object_friendly_type, validator_function)


@register_policy_fixer("DeleteUnusedServices", "Delete Service objects that aren't in use")
def delete_unused_services(profilepackage):
    object_type = "Services"
    object_friendly_type = "Service"
    _, _, validator_function = get_policy_validators()['UnusedServices']
    return delete_unused_object(profilepackage, object_type, object_friendly_type, validator_function)


@register_policy_fixer("DeleteUnusedServiceGroups", "Delete Service Group objects that aren't in use")
def delete_unused_servicegroups(profilepackage):
    object_type = "ServiceGroups"
    object_friendly_type = "Service Groups"
    _, _, validator_function = get_policy_validators()['UnusedServiceGroups']
    return delete_unused_object(profilepackage, object_type, object_friendly_type, validator_function)


@register_policy_fixer("DeleteUnusedObjects", "Convenience wrapper that calls DeleteUnusedAddressGroups, DeleteUnusedAddresses, DeleteUnusedServiceGroups, and DeleteUnusedServices")
def delete_unused_objects(profilepackage):
    deleted_objects = []
    deleted_objects += delete_unused_addressgroups(profilepackage)
    deleted_objects += delete_unused_addresses(profilepackage)
    deleted_objects += delete_unused_servicegroups(profilepackage)
    deleted_objects += delete_unused_services(profilepackage)
    return deleted_objects
