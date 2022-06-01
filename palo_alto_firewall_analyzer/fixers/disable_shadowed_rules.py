from palo_alto_firewall_analyzer.core import register_policy_fixer, get_policy_validators, xml_object_to_dict
from palo_alto_firewall_analyzer import pan_api


@register_policy_fixer("DisableShadowedRules", "Disable shadowed rules")
def remove_redundant_rule_services(profilepackage):
    panorama = profilepackage.settings.get("Panorama")
    api_key = profilepackage.api_key
    pan_config = profilepackage.pan_config
    version = pan_config.get_major_version()

    _, _, validator_function = get_policy_validators()['ShadowingRules']
    print("*"*80)
    print("Checking for redundant rule members")

    rules_to_update = validator_function(profilepackage)

    print(f"Disabling {len(rules_to_update)} Policies")
    for badentry in rules_to_update:
        shadowed_tuple = badentry.data[0]
        device_group, ruletype, rule_name, rule_entry = shadowed_tuple
        disabled = (rule_entry.find('disabled') is not None and rule_entry.find('disabled').text == 'yes')
        if not disabled:
            policy_dict = xml_object_to_dict(rule_entry)['entry']
            policy_dict['disabled'] = 'yes'
            print(f"Disabling {device_group}'s {ruletype} {rule_name}")
            pan_api.update_devicegroup_policy(panorama, version, api_key, policy_dict, ruletype, device_group)
    pan_api.validate_commit(panorama, api_key)
    print("Disabling complete. Please commit in the firewall.")
    return rules_to_update
