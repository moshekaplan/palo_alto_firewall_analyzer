from palo_alto_firewall_analyzer.core import register_policy_fixer, get_policy_validators, xml_object_to_dict
from palo_alto_firewall_analyzer import pan_api


@register_policy_fixer("RemoveRedundantRuleMembers", "Remove redundant rule members")
def remove_redundant_rule_members(profilepackage):
    panorama = profilepackage.settings.get("Panorama")
    api_key = profilepackage.api_key
    pan_config = profilepackage.pan_config
    version = pan_config.get_major_version()

    _, _, validator_function = get_policy_validators()['RedundantRuleMembers']
    print("*"*80)
    print("Checking for redundant rule members")

    rules_to_update = validator_function(profilepackage)

    print(f"Replacing the contents of {len(rules_to_update)} Policies")
    for badentry in rules_to_update:
        object_policy_dg = badentry.device_group
        rule_type, rule_entry, members_to_remove = badentry.data
        rule_dict = xml_object_to_dict(rule_entry)
        for direction, member_and_containing_pairs in members_to_remove.items():
            for member_and_containing in member_and_containing_pairs:
                member, _ = member_and_containing
                rule_dict['entry'][direction]['member'].remove(member)
        pan_api.update_devicegroup_policy(panorama, version, api_key, rule_dict, rule_type, object_policy_dg)
    pan_api.validate_commit(panorama, api_key)
    print("Replacement complete. Please commit in the firewall.")
    return rules_to_update
