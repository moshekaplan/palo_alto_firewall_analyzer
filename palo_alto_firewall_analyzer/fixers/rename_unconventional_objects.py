from palo_alto_firewall_analyzer.core import register_policy_fixer, get_policy_validators
from palo_alto_firewall_analyzer import pan_api

import requests


@register_policy_fixer("RenameUnconventionallyNamedServices", "Rename unconventional Services")
def rename_unconventional_services(profilepackage):
    panorama = profilepackage.settings.get("Panorama")
    api_key = profilepackage.api_key
    pan_config = profilepackage.pan_config
    version = pan_config.get_major_version()

    _, _, validator_function = get_policy_validators()['UnconventionallyNamedServices']
    services_to_rename = validator_function(profilepackage)
    if not services_to_rename:
        return services_to_rename

    print(f"Renaming {len(services_to_rename)} services now")
    for service_entry in services_to_rename:
        device_group = service_entry.device_group
        old_name = service_entry.data[0].get('name')
        new_name = service_entry.data[1]

        print(f"Renaming Device Group {device_group}'s Service from {old_name} to {new_name}")
        try:
            pan_api.rename_object(panorama, version, api_key, 'Services', old_name, new_name, device_group)
        except requests.HTTPError as err:
            print(f"Error Renaming {device_group}'s Service {old_name}: {err.response.text}")
    pan_api.validate_commit(panorama, api_key)

    return services_to_rename
