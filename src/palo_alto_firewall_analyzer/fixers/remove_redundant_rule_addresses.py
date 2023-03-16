import logging

from palo_alto_firewall_analyzer.core import register_policy_fixer, get_policy_validators, xml_object_to_dict
from palo_alto_firewall_analyzer import pan_api

logger = logging.getLogger(__name__)

@register_policy_fixer("RemoveRedundantRuleAddresses", "Remove redundant rule addresses")
def remove_redundant_rule_members(profilepackage):
    panorama = profilepackage.settings.get("Panorama")
    api_key = profilepackage.api_key
    pan_config = profilepackage.pan_config
    version = pan_config.get_major_version()

    _, _, validator_function = get_policy_validators()['RedundantRuleAddresses']
    logger.info("*"*80)
    logger.info("Checking for redundant rule addresses")

    rules_to_update = validator_function(profilepackage)

    logger.info(f"Replacing the contents of {len(rules_to_update)} Policies")
    for badentry in rules_to_update:
        object_policy_dg = badentry.device_group
        rule_type, rule_entry, members_to_remove = badentry.data
        rule_dict = xml_object_to_dict(rule_entry)['entry']
        for direction, member_and_containing_pairs in members_to_remove.items():
            for member, _ in member_and_containing_pairs:
                # It's possible a member is contained in two of a rule's address groups
                if member in rule_dict[direction]['member']:
                    rule_dict[direction]['member'].remove(member)
        pan_api.update_devicegroup_policy(panorama, version, api_key, rule_dict, rule_type, object_policy_dg)
    pan_api.validate_commit(panorama, api_key)
    logger.info("Replacement complete. Please commit in the firewall.")
    return rules_to_update
