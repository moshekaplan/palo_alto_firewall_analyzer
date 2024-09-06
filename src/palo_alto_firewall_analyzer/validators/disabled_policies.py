import logging

from palo_alto_firewall_analyzer.core import BadEntry, register_policy_validator
from palo_alto_firewall_analyzer.scripts.pan_details import parsed_details

logger = logging.getLogger(__name__)


@register_policy_validator("DisabledPolicies", "Policy objects that are disabled")
def find_disabled_policies(profilepackage):
    device_groups = profilepackage.device_groups
    pan_config = profilepackage.pan_config
    ignored_disabled_rules = set(profilepackage.settings.get('Ignored Disabled Policies', "").split(','))

    policies_to_delete = []
    count_policies = 0
    
    for device_group in device_groups:
        for policy_type in pan_config.SUPPORTED_POLICY_TYPES:
            policies = pan_config.get_devicegroup_policy(policy_type, device_group)
            
            for policy_entry in policies:                
                disabled = (policy_entry.find('disabled') is not None and policy_entry.find('disabled').text == 'yes')
                if disabled:
                    policy_name = policy_entry.get('name')
                    if policy_name in ignored_disabled_rules:            
                        continue
                    text = f"Device Group {device_group}'s {policy_type} \"{policy_name}\" is disabled"
                    detail = {
                        "policy_type":policy_type, 
                        "policy_name":policy_name,
                        "device_group":device_group,
                        "entry_type":policy_type
                        }
                    policy_to_delete = BadEntry(data=[policy_entry], text=text, device_group=device_group, entry_type=policy_type, Detail=parsed_details(detail))
                    policies_to_delete.append(policy_to_delete)
                count_policies+=1
                
    return policies_to_delete, count_policies
