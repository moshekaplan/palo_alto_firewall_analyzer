from palo_alto_firewall_analyzer.core import register_policy_fixer, get_policy_validators
from palo_alto_firewall_analyzer import pan_api

import requests


def rename_unconventional_object(profilepackage, validator_name, object_type, object_friendly_name):
    panorama = profilepackage.settings.get("Panorama")
    api_key = profilepackage.api_key
    pan_config = profilepackage.pan_config
    version = pan_config.get_major_version()

    _, _, validator_function = get_policy_validators()[validator_name]
    objects_to_rename = validator_function(profilepackage)
    if not objects_to_rename:
        return objects_to_rename

    print(f"Renaming {len(objects_to_rename)} {object_friendly_name} now")
    for object_entry in objects_to_rename:
        device_group = object_entry.device_group
        old_name = object_entry.data[0].get('name')
        new_name = object_entry.data[1]

        print(f"Renaming Device Group {device_group}'s {object_friendly_name} from {old_name} to {new_name}")
        try:
            pan_api.rename_object(panorama, version, api_key, object_type, old_name, new_name, device_group)
        except requests.HTTPError as err:
            print(f"Error Renaming {device_group}'s {object_friendly_name} {old_name}: {err.response.text}")
    pan_api.validate_commit(panorama, api_key)

    return objects_to_rename

@register_policy_fixer("RenameUnconventionallyNamedServices", "Rename unconventional Services")
def rename_unconventional_services(profilepackage):
    validator_name = 'UnconventionallyNamedServices'
    object_type = 'Services'
    object_friendly_name = 'Service'
    return rename_unconventional_object(profilepackage, validator_name, object_type, object_friendly_name)


@register_policy_fixer("RenameUnconventionallyNamedAddresses", "Rename unconventional Addresses")
def rename_unconventional_services(profilepackage):
    validator_name = 'UnconventionallyNamedAddresses'
    object_type = 'Addresses'
    object_friendly_name = 'Address'
    return rename_unconventional_object(profilepackage, validator_name, object_type, object_friendly_name)
