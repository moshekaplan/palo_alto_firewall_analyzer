import logging

import requests

from palo_alto_firewall_analyzer.core import register_policy_fixer, get_policy_validators
from palo_alto_firewall_analyzer import pan_api

logger = logging.getLogger(__name__)

@register_policy_fixer("DeleteDisabledPolicies", "Delete disabled policies")
def delete_disabled_policies(profilepackage):
    panorama = profilepackage.settings.get("Panorama")
    api_key = profilepackage.api_key
    pan_config = profilepackage.pan_config
    version = pan_config.get_major_version()

    _, _, validator_function = get_policy_validators()['DisabledPolicies']
    policies_to_delete = validator_function(profilepackage)
    if policies_to_delete:
        logger.info (f"Deleting {len(policies_to_delete)} disabled policies now")
        for policy_entry in policies_to_delete:
            device_group = policy_entry.device_group
            policy_name = policy_entry.data[0].get('name')
            policy_type = policy_entry.entry_type

            logger.info(f"Deleting Device Group {device_group}'s {policy_type} {policy_name}")
            try:
                pan_api.delete_policy(panorama, version, api_key, policy_type, policy_name, device_group)
            except requests.HTTPError as err:
                logger.info(f"Error deleting {device_group}'s {policy_type} {policy_name}: {err.response.text}")
        pan_api.validate_commit(panorama, api_key)

    return policies_to_delete
