'''
Detects Shadowed rules

A rule is shadowed if it is preceeded by a broader rule
that would match all traffic that the rule would match.

For example, Rule 2 below would be a shadowed rule:

Rule 1:
Allow * to 192.168.1.0/24

Rule 2:
Allow * to 192.168.1.3/32

Some notes:
This implementation is very simple: It looks
for a single preceeding rule that is broader than a following rule. A more
intelligent algorithm would be able to combine all previous
rules and use a solver like Z3 to determine which combination
of previous rules would provide the same coverage as the shadowed rule.

It also doesn't resolve FQDNs, because their resolved address can
change and so that would lead to inconsistent results.

A future enhancement would be to also check IP ranges and subnets, so that
127.0.0.0/24 would also be detected as shadowing 127.0.0.1/32.
'''


from palo_alto_firewall_analyzer.core import BadEntry, register_policy_validator


def get_contained_objects(group_name, all_groups_to_members):
    """Given a the name of an AddressGroup or ServiceGroup, retrieves a set of all the names of objects effectively contained within"""
    # Note: Same code as from group_replacements.py
    contained_members = []
    for member in all_groups_to_members[group_name]:
        if member in all_groups_to_members:
            # do NOT include the Group member itself
            # contained_members += [member]
            contained_members += get_contained_objects(member, all_groups_to_members)
        else:
            contained_members += [member]
    return set(contained_members)


def build_group_member_mapping(pan_config, device_group, object_type):
    """Creates a mapping of AddressGroup or ServiceGroup objects to the underlying objects"""
    # Note: Original code from group_replacements.py
    object_type_to_xpaths = {'AddressGroups': ['./static/member', './dynamic/filter'],
                             'ServiceGroups': ['./members/member'],
                             'ApplicationGroups': ['./members/member']
                             }
    all_groups_to_members = {}
    for group_entry in pan_config.get_devicegroup_all_objects(object_type, device_group):
        name = group_entry.get('name')
        members = []
        for xpath in object_type_to_xpaths[object_type]:
            members += [member.text for member in group_entry.findall(xpath)]
        all_groups_to_members[name] = members

    group_to_contained_members = {}
    for group_name in all_groups_to_members:
        group_to_contained_members[group_name] = get_contained_objects(group_name, all_groups_to_members)
    return group_to_contained_members


def replace_groups_with_underlying_members(members, mappings):
    output = []
    for member in members:
        output += mappings.get(member, [member])
    return output


def get_all_rules_for_dg(pan_config, device_group):
    """
    Per https://docs.paloaltonetworks.com/panorama/9-1/panorama-admin/panorama-overview/centralized-firewall-configuration-and-update-management/device-groups/device-group-policies
    The order is: pre-rules top-down, local rules, then post-rules bottom up.

    :param pan_config: PanConfig instance
    :param device_group: Device Group to get rules for
    :return: List of tuples: (device group, rule type, rule entry)
    """

    _, device_group_hierarchy_parent = pan_config.get_device_groups_hierarchy()

    dg_hierarchy = [device_group]
    current_dg = device_group_hierarchy_parent.get(device_group)
    while current_dg:
        dg_hierarchy.append(current_dg)
        current_dg = device_group_hierarchy_parent.get(current_dg)

    # Now that we have the DG hierarchy, we can build the list of rules:
    all_rules = []
    rule_type = 'SecurityPreRules'
    for dg in dg_hierarchy[::-1]:
        for rule in pan_config.get_devicegroup_policy(rule_type, dg):
            all_rules += [(dg, rule_type, rule)]

    # Doesn't support local rules, since those are stored on the firewall

    rule_type = 'SecurityPostRules'
    for dg in dg_hierarchy:
        for rule in pan_config.get_devicegroup_policy(rule_type, dg):
            all_rules += [(dg, rule_type, rule)]
    return all_rules


def transform_rules(rules, addressgroups_to_underlying_addresses, applicationgroups_to_underlying_services, servicegroups_to_underlying_services):
    """Transforms a list of rules into a list of tuples with
    a frozenset for each field, to detect if a rule shadows another.
    """
    transformed_rules = []
    for device_group, ruletype, rule_entry in rules:
        # Disabled rules can be ignored
        if rule_entry.find("./disabled") is not None and rule_entry.find("./disabled").text == "yes":
            continue

        rule_name = rule_entry.get('name')
        rule_values = {}
        rule_values['negate'] = frozenset([elem.text for elem in rule_entry.findall('./target/negate')])
        rule_values['negate-source'] = frozenset([elem.text for elem in rule_entry.findall('./negate-source')])
        rule_values['src_zones'] = frozenset([elem.text for elem in rule_entry.findall('./from/member')])
        rule_values['src_members'] = frozenset(replace_groups_with_underlying_members([elem.text for elem in rule_entry.findall('./source/member')], addressgroups_to_underlying_addresses))
        rule_values['source_hip'] = frozenset([elem.text for elem in rule_entry.findall('./source-hip/member')])
        rule_values['users'] = frozenset([elem.text for elem in rule_entry.findall('./source-user/')])
        rule_values['negate-destination'] = frozenset([elem.text for elem in rule_entry.findall('./negate-destination')])
        rule_values['dest_zones'] = frozenset([elem.text for elem in rule_entry.findall('./to/member')])
        rule_values['dest_members'] = frozenset(replace_groups_with_underlying_members([elem.text for elem in rule_entry.findall('./destination/member')], addressgroups_to_underlying_addresses))
        rule_values['destination_hip'] = frozenset([elem.text for elem in rule_entry.findall('./destination-hip/member')])
        rule_values['application'] = frozenset(replace_groups_with_underlying_members([elem.text for elem in rule_entry.findall('./application/')], applicationgroups_to_underlying_services))
        rule_values['service'] = frozenset(replace_groups_with_underlying_members([elem.text for elem in rule_entry.findall('./service/')], servicegroups_to_underlying_services))
        rule_values['url_category'] = frozenset([elem.text for elem in rule_entry.findall('./category/')])
        rule_values['rule_type'] = frozenset([elem.text for elem in rule_entry.findall('./rule-type')])
        # Assign default values if not present:
        if not rule_values['negate-source']:
            rule_values['negate-source'] = frozenset(["no"])
        if not rule_values['negate-destination']:
            rule_values['negate-destination'] = frozenset(["no"])
        if not rule_values['rule_type']:
            rule_values['rule_type'] = frozenset(["universal"])
        transformed_rules.append((device_group, ruletype, rule_name, rule_entry, rule_values))
    return transformed_rules


def is_shadowing(prior_rule, current_rule):
    """Returns True if all values in the current
    rule are contained in the prior rule"""
    # Sanity check that they have the same values
    if prior_rule.keys() != current_rule.keys():
        return False

    for attr in prior_rule.keys():
        if not ('any' in prior_rule[attr] or prior_rule[attr] >= current_rule[attr]):
            return False
    return True


def find_shadowing(device_group, transformed_rules):
    """
    :param device_group: Only report on prerules and postrules in this device group,
    which are shadowed by others
    :param transformed_rules: list of transformed rules to examine for shadowing
    :return:
    """
    shadowing_rules = []
    for i, rule_tuple in enumerate(transformed_rules):
        dg, ruletype, rule_name, rule_entry, rule_values = rule_tuple
        # Move forward until we get to the device group we're examining
        if dg != device_group:
            continue
        # Now check if this rule is shadowed by any of the preceeding rules:
        shadowed_by = []
        for prior_dg, prior_ruletype, prior_rule_name, prior_rule_entry, prior_rule_values in transformed_rules[:i]:
            if is_shadowing(prior_rule_values, rule_values):
                shadowed_by += [(prior_dg, prior_ruletype, prior_rule_name, prior_rule_entry)]
        if shadowed_by:
            shadowing_rules.append([(dg, ruletype, rule_name, rule_entry), shadowed_by])
    return shadowing_rules


@register_policy_validator("ShadowingRules",
                           "Shadowing Rules: Detects a broader rule followed by a narrower rule")
def find_shadowing_rules(profilepackage):
    device_groups = profilepackage.device_groups
    pan_config = profilepackage.pan_config

    badentries = []

    print("*" * 80)
    print("Checking for shadowing rules")

    for i, device_group in enumerate(device_groups):
        print(f"Checking Device group {device_group}")
        # As security rules are inherited from parent device groups, we'll need to check those too
        all_rules = get_all_rules_for_dg(pan_config, device_group)
        # Filter disabled rules:
        all_rules = [(dg, rule_type, rule) for (dg, rule_type, rule) in all_rules if rule.find("./disabled") is None or rule.find("./disabled").text != "yes"]
        if not all_rules:
            continue
        addressgroups_to_underlying_addresses = build_group_member_mapping(pan_config, device_group, 'AddressGroups')
        servicegroups_to_underlying_services = build_group_member_mapping(pan_config, device_group, 'ServiceGroups')
        applicationgroups_to_underlying_services = build_group_member_mapping(pan_config, device_group, 'ApplicationGroups')
        transformed_rules = transform_rules(all_rules, addressgroups_to_underlying_addresses, applicationgroups_to_underlying_services, servicegroups_to_underlying_services)

        shadowing_rules = find_shadowing(device_group, transformed_rules)

        # Report overlapping rules
        for shadowed_tuple, prior_tuples in shadowing_rules:
            dg, ruletype, rule_name, rule_entry = shadowed_tuple
            text = f"{dg}'s {ruletype} '{rule_name}' is shadowed by: "
            shadowing_list = []
            for prior_tuple in prior_tuples:
                prior_dg, prior_ruletype, prior_rule_name, prior_rule_entry = prior_tuple
                shadowing_list += [f"{prior_dg}'s {prior_ruletype} '{prior_rule_name}'"]
            text += ", ".join(shadowing_list)
            print(text)
            badentries.append(
                BadEntry(data=(shadowed_tuple, prior_tuples), text=text, device_group=device_group, entry_type=None))

    return badentries
