import logging

from palo_alto_firewall_analyzer.core import BadEntry, register_policy_validator
from palo_alto_firewall_analyzer.scripts.pan_details import parsed_details
logger = logging.getLogger(__name__)

@register_policy_validator("BadLogSetting", "Rule uses an incorrect log profile")
def find_bad_log_setting(profilepackage):
    mandated_log_profile = profilepackage.settings.get('Mandated Logging Profile')
    device_groups = profilepackage.device_groups
    pan_config = profilepackage.pan_config
    count_checks = 0 
    if not mandated_log_profile:
        return [],count_checks

    badentries = []

    logger.info("*" * 80)
    logger.info("Checking for incorrect log settings")

    for i, device_group in enumerate(device_groups):
        for ruletype in ('SecurityPreRules', 'SecurityPostRules'):
            rules = pan_config.get_devicegroup_policy(ruletype, device_group)
            logger.info(f"({i+1}/{len(device_groups)}) Checking {device_group}'s {ruletype}")

            for entry in rules:
                count_checks+=1
                rule_name = entry.get('name')
                # Disabled rules can be ignored
                if entry.find("./disabled") is not None and entry.find("./disabled").text == "yes":
                    continue

                log_setting_node = entry.find("./log-setting")

                if log_setting_node is not None:
                    log_setting = log_setting_node.text
                else:
                    log_setting = None

                if mandated_log_profile == 'default' and log_setting is None:
                    # 'default' has special treatment, in that if the 'default'
                    # profile exists, entries without a value will automatically
                    # use the 'default' log profile.
                    continue
                elif log_setting is None:
                    text = f"Device Group {device_group}'s {ruletype} '{rule_name}' doesn't use any log profile!"
                    logger.debug(text)
                    detail={
                        "device_group":device_group,
                        "rule_type":ruletype,
                        "rule_name":rule_name,
                        "entry_type":ruletype
                        }
                    badentries.append(BadEntry(data=[entry, mandated_log_profile], text=text, device_group=device_group, entry_type=ruletype, Detail=parsed_details(detail)))
                elif log_setting != mandated_log_profile:
                    text = f"Device Group {device_group}'s {ruletype} '{rule_name}' doesn't use log profile '{mandated_log_profile}', instead it uses '{log_setting}'"
                    logger.debug(text)
                    detail={
                        "device_group":device_group,
                        "rule_type":ruletype,
                        "rule_name":rule_name,
                        "entry_type":ruletype,
                        "mandated_log_profile":mandated_log_profile,
                        "log_setting":log_setting
                        }
                    badentries.append(BadEntry(data=[entry, mandated_log_profile], text=text, device_group=device_group, entry_type=ruletype, Detail=parsed_details(detail)))

    return badentries,count_checks
