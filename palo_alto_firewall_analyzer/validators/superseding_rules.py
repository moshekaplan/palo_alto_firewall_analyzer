from palo_alto_firewall_validator.core import BadEntry, register_policy_validator


def get_all_rules_for_dg(device_group, device_group_hierarchy_parent, devicegroup_objects):
    """
    Per https://docs.paloaltonetworks.com/panorama/9-1/panorama-admin/panorama-overview/centralized-firewall-configuration-and-update-management/device-groups/device-group-policies
    The order is: pre-rules top-down, local rules, then post-rules bottom up.

    :param device_group: Device Group to get rules for
    :param device_group_hierarchy_parent: dict mapping device group to parent device groups
    :param devicegroup_objects:
    :return: List of tuples: (device group, rule type, rule entry)
    """
    dg_hierarchy = [device_group]
    current_dg = device_group_hierarchy_parent.get(device_group)
    while current_dg:
        dg_hierarchy.append(current_dg)
        current_dg = device_group_hierarchy_parent.get(current_dg)

    all_rules = []
    rule_type = 'SecurityPreRules'
    for dg in dg_hierarchy[::-1]:
        for rule in devicegroup_objects[dg][rule_type]:
            all_rules += [(dg, rule_type, rule)]

    # Doesn't support local rules yet

    rule_type = 'SecurityPostRules'
    for dg in dg_hierarchy:
        for rule in devicegroup_objects[dg][rule_type]:
            all_rules += [(dg, rule_type, rule)]

    return all_rules


def is_superseding(obj1, obj2):
    """Returns True if all keys in obj1
    are present in obj2 and all of the sets
    those obj1's keys map to are supersets of the
    sets obj2's keys map to"""
    if obj1.keys() != obj2.keys():
        return False

    for attr in obj1.keys():
        if not ('any' in obj1[attr] or obj1[attr] >= obj2[attr]):
            return False
    return True


def find_superseding(device_group_filter, transformed_rules):
    """
    :param device_group_filter: Only report on prerules and postrules in this device group,
    which are superseded by others
    :param transformed_rules: list of transformed rules to examine for superseding
    :return:
    """
    superseding_rules = []
    for i, rule_tuple in enumerate(transformed_rules):
        dg, ruletype, rule_name, rule_entry, rule_values = rule_tuple
        for prior_dg, prior_ruletype, prior_rule_name, prior_rule_entry, prior_rule_values in transformed_rules[:i]:
            # Only compare the rules in the device group of interest
            if prior_dg != device_group_filter:
                continue
            if is_superseding(rule_values, prior_rule_values):
                superseding_rules.append([(prior_dg, prior_ruletype, prior_rule_name, prior_rule_entry),
                                          (dg, ruletype, rule_name, rule_entry)])
    return superseding_rules


def transform_rules(rules):
    """Transforms a list of rules into a list of tuples with
    a frozenset for each field, to detect if a rule supersedes another.
    """
    transformed_rules = []
    for device_group, ruletype, rule_entry in rules:
        # Disabled rules can be ignored
        if rule_entry.find("./disabled") is not None and rule_entry.find("./disabled").text == "yes":
            continue

        rule_name = rule_entry.get('name')
        rule_values = {}
        rule_values['src_zones'] = frozenset([elem.text for elem in rule_entry.findall('./from/member')])
        rule_values['src_members'] = frozenset([elem.text for elem in rule_entry.findall('./source/member')])
        rule_values['users'] = frozenset([elem.text for elem in rule_entry.findall('./source-user/')])
        rule_values['dest_zones'] = frozenset([elem.text for elem in rule_entry.findall('./to/member')])
        rule_values['dest_members'] = frozenset([elem.text for elem in rule_entry.findall('./destination/member')])
        rule_values['application'] = frozenset([elem.text for elem in rule_entry.findall('./application/')])
        rule_values['service'] = frozenset([elem.text for elem in rule_entry.findall('./service/')])
        rule_values['url_category'] = frozenset([elem.text for elem in rule_entry.findall('./category/')])
        rule_values['action'] = frozenset([elem.text for elem in rule_entry.findall('./action')])
        transformed_rules.append((device_group, ruletype, rule_name, rule_entry, rule_values))
    return transformed_rules


@register_policy_validator("SupersedingRules",
                           "Superseding Rules: Detects a narrow rule followed by a more-broad rule")
def find_superseding_rules(profilepackage):
    device_groups = profilepackage.device_groups
    devicegroup_objects = profilepackage.devicegroup_objects
    device_group_hierarchy_parent = profilepackage.device_group_hierarchy_parent

    badentries = []

    print("*" * 80)
    print("Checking for Superseding rules")

    for i, device_group in enumerate(device_groups):
        print(f"Checking Device group {device_group}")
        # As security rules are inherited from parent device groups, we'll need to check those too
        all_rules = get_all_rules_for_dg(device_group, device_group_hierarchy_parent, devicegroup_objects)
        transformed_rules = transform_rules(all_rules)
        superseding_rules = find_superseding(device_group, transformed_rules)

        # Report overlapping rules
        for prior_tuple, superseding_tuple in superseding_rules:
            prior_dg, prior_ruletype, prior_rule_name, prior_rule_entry = prior_tuple
            dg, ruletype, rule_name, rule_entry = superseding_tuple

            text = f"{prior_dg}'s {prior_ruletype} '{prior_rule_name}' is superseded by {dg}'s {ruletype} '{rule_name}'"
            print(text)
            badentries.append(
                BadEntry(data=(prior_tuple, superseding_tuple), text=text, device_group=device_group, entry_type=None))

    return badentries
