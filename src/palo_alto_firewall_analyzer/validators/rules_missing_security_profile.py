import collections
import logging

from palo_alto_firewall_analyzer.core import BadEntry, register_policy_validator
from palo_alto_firewall_analyzer.core import xml_object_to_dict

logger = logging.getLogger(__name__)

@register_policy_validator("RulesMissingSecurityProfile", "Detect rules with no Security Profile Groups attached")
def find_missing_group_profile(profilepackage):
    device_groups = profilepackage.device_groups
    pan_config = profilepackage.pan_config

    logger.info("*"*80)
    logger.info("Checking for rules with no security profiles attached")

    badentries = []
    device_groups_to_ruletypes_to_policies_needing_updates = {}
    for i, device_group in enumerate(device_groups):
        device_groups_to_ruletypes_to_policies_needing_updates[device_group] = collections.defaultdict(list)
        for ruletype in ('SecurityPreRules', 'SecurityPostRules'):
            rules = pan_config.get_devicegroup_policy(ruletype, device_group)
            logger.info(f"({i+1}/{len(device_groups)}) Checking {device_group}'s {ruletype}")

            for entry in rules:
                rule_name = entry.get('name')

                disabled = (entry.find('disabled') is not None and entry.find('disabled').text == 'yes')

                # Disabled rules can be ignored
                if disabled == 'yes':
                    continue

                # Only allow rules trigger security profile groups
                # So we only care about 'allow' rules missing a security profile group
                action = [elem.text for elem in entry.findall('./action')]
                if action != ['allow']:
                    continue

                # Check if either there is no Security Profile Group or Security Profile assigned
                profile_or_group_missing = entry.find('profile-setting/') is None
                # Check if the policy is set to "Group", but with a value of "None"
                group_empty = entry.find('profile-setting/group/') is None
                if not (profile_or_group_missing or group_empty):
                    continue

                # If we're here, that means:
                # 1) The rule is not disabled
                # 2) The rule is used to allow traffic
                # 3) The rule does not have any security profile group or profile attached
                text = f"Device Group {device_group}'s {ruletype} '{rule_name}' does not have a Security Profile Group attached!"
                logger.info(text)
                badentries.append( BadEntry(data=entry, text=text, device_group=device_group, entry_type=ruletype) )
    return badentries
