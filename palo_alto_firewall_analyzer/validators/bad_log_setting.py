from palo_alto_firewall_analyzer.core import BadEntry, register_policy_validator


@register_policy_validator("BadLogSetting", "Rule uses an incorrect log profile")
def find_bad_log_setting(profilepackage):
    mandated_log_profile = profilepackage.mandated_log_profile
    device_groups = profilepackage.device_groups
    devicegroup_exclusive_objects = profilepackage.devicegroup_exclusive_objects
    verbose = profilepackage.verbose

    badentries = []
    if verbose:
        print ("*"*80)
        print ("Checking for incorrect log settings")

    for i, device_group in enumerate(device_groups):
        for ruletype in ('SecurityPreRules', 'SecurityPostRules'):
            rules = devicegroup_exclusive_objects[device_group][ruletype]
            if verbose:
                print (f"({i+1}/{len(device_groups)}) Checking {device_group}'s {ruletype}")

            for entry in rules:
                rule_name = entry.get('name')
                # Disabled rules can be ignored
                if entry.find("./disabled") is not None and entry.find("./disabled").text == "yes":
                    continue

                log_setting_node = entry.find("./log-setting")


                if log_setting_node is not None:
                    log_setting = log_setting_node.text
                elif mandated_log_profile == 'default':
                    # 'default' has special treatment, in that if the 'default'
                    # profile exists, entries without a value will automatically
                    # use the 'default' log profile.
                    continue
                else:
                    log_setting = None

                if mandated_log_profile and log_setting != mandated_log_profile:
                    text = f"Device Group {device_group}'s {ruletype} '{rule_name}' doesn't use log profile '{mandated_log_profile}', instead it uses '{log_setting}'"
                    if verbose:
                        print(text)
                    badentries.append( BadEntry(data=entry, text=text, device_group=device_group, entry_type=ruletype) )
                elif log_setting is None:
                    text = f"Device Group {device_group}'s {ruletype} '{rule_name}' doesn't use any log profile!"
                    if verbose:
                        print (text)
                    badentries.append( BadEntry(data=entry, text=text, device_group=device_group, entry_type=ruletype) )
    return badentries