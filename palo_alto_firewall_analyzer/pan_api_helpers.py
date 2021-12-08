import functools
import getpass

from palo_alto_firewall_analyzer import pan_api
from palo_alto_firewall_analyzer.pan_config import PanConfig
from palo_alto_firewall_analyzer.core import squash_all_devicegroups, ProfilePackage


def load_config_package(config, api_key, device_group, limit, verbose):
    panorama = config['Panorama']
    mandated_log_profile = config.get('Mandated Logging Profile')
    if config.get('Allowed Group Profiles'):
        allowed_group_profiles = config.get('Allowed Group Profiles').split(',')
    else:
        allowed_group_profiles = tuple()
    default_group_profile = config.get('Default Group Profile')

    if config.get('Ignored DNS Prefixes'):
        ignored_dns_prefixes = tuple([prefix.lower() for prefix in config.get('Ignored DNS Prefixes','').split(',')])
    else:
        ignored_dns_prefixes = tuple()

    config_file = pan_api.export_configuration2(panorama, api_key)
    pan_config = PanConfig(config_file)

    device_group_hierarchy_children, device_group_hierarchy_parent = pan_api.get_device_groups_hierarchy(panorama,
                                                                                                         api_key)

    device_groups_and_firewalls = pan_api.get_device_groups_and_firewalls(panorama, api_key)
    active_firewalls = pan_api.get_active_firewalls(panorama, api_key)

    # Build the mapping of active FWs in each device group
    active_firewalls_per_devicegroup = {}
    for dg, firewalls in device_groups_and_firewalls.items():
        active_firewalls_per_devicegroup[dg] = [fw for fw in firewalls if fw in active_firewalls]

    # Build a mapping of device groups to their 'parent' device groups
    # dgs_in_hierarchy = []
    # current_dg = device_group
    # while current_dg in device_group_hierarchy_parent:
    #    dgs_in_hierarchy.append(device_group_hierarchy_parent[current_dg])
    #    current_dg = device_group_hierarchy_parent[current_dg]

    # Build a mapping of device groups to their 'child' device groups
    devicegroups_to_child_devicegroups = squash_all_devicegroups(device_groups_and_firewalls,
                                                                 device_group_hierarchy_children,
                                                                 device_group_hierarchy_parent)

    all_active_firewalls_per_devicegroup = {}
    for dg, child_dgs in devicegroups_to_child_devicegroups.items():
        all_active_firewalls_per_devicegroup[dg] = []
        for child_dg in child_dgs:
            all_active_firewalls_per_devicegroup[dg] += active_firewalls_per_devicegroup[child_dg]

    # Create and fill in the devicegroup_objects, which represents all entries, per devicegroup
    devicegroup_objects = {}

    all_devicegroups = sorted(list(device_groups_and_firewalls.keys()))
    if device_group:
        device_groups = [device_group]
    else:
        device_groups = all_devicegroups

    for device_group in all_devicegroups:
        devicegroup_objects[device_group] = {}
        devicegroup_objects[device_group]['all_child_device_groups'] = devicegroups_to_child_devicegroups[device_group]
        devicegroup_objects[device_group]['all_active_child_firewalls'] = all_active_firewalls_per_devicegroup[
            device_group]

        if device_group == 'shared':
            for policy_type in pan_config.SUPPORTED_POLICY_TYPES:
                devicegroup_objects[device_group][policy_type] = \
                    pan_config.get_devicegroup_policy(policy_type, 'shared')[:limit]
            for object_type in pan_config.SUPPORTED_OBJECT_TYPES:
                devicegroup_objects[device_group][object_type] = \
                    pan_config.get_devicegroup_object(object_type, 'shared')
        else:
            for policy_type in pan_config.SUPPORTED_POLICY_TYPES:
                devicegroup_objects[device_group][policy_type] = \
                    pan_config.get_devicegroup_policy(policy_type, 'device-group', device_group)[:limit]
            for object_type in pan_config.SUPPORTED_OBJECT_TYPES:
                devicegroup_objects[device_group][object_type] = \
                    pan_config.get_devicegroup_object(object_type, 'device-group', device_group)

    rule_limit_enabled = limit is not None

    # Build a listing of policy objects that are exclusive to each device group, which won't include policies inherited from the parent device groups
    devicegroup_exclusive_objects = {}
    for device_group in all_devicegroups:
        devicegroup_exclusive_objects[device_group] = {}

        for policy_type in pan_config.SUPPORTED_POLICY_TYPES:
            if device_group not in device_group_hierarchy_parent:
                # No parent means no inherited policies
                devicegroup_exclusive_objects[device_group][policy_type] = devicegroup_objects[device_group][
                    policy_type]
            else:
                parent_dg = device_group_hierarchy_parent[device_group]
                parent_policy_uuids = set([entry.get('@uuid') for entry in devicegroup_objects[parent_dg][policy_type]])
                exclusive_objects = [entry for entry in devicegroup_objects[device_group][policy_type] if
                                     entry.get('@uuid') not in parent_policy_uuids]
                devicegroup_exclusive_objects[device_group][policy_type] = exclusive_objects

    profilepackage = ProfilePackage(
        panorama=panorama,
        api_key=api_key,
        pan_config=pan_config,
        mandated_log_profile=mandated_log_profile,
        allowed_group_profiles=allowed_group_profiles,
        default_group_profile=default_group_profile,
        ignored_dns_prefixes=ignored_dns_prefixes,
        device_group_hierarchy_children=device_group_hierarchy_children,
        device_group_hierarchy_parent=device_group_hierarchy_parent,
        device_groups_and_firewalls=device_groups_and_firewalls,
        device_groups=device_groups,
        devicegroup_objects=devicegroup_objects,
        devicegroup_exclusive_objects=devicegroup_exclusive_objects,
        rule_limit_enabled=rule_limit_enabled,
        verbose=verbose
    )
    return profilepackage


@functools.lru_cache(maxsize=None)
def get_firewall_zone(firewall, api_key, ip):
    interface = pan_api.get_interface(firewall, api_key, ip)
    zone = pan_api.get_interface_zone(firewall, api_key, interface)
    return zone


def get_and_save_API_key(output):
    print("Please enter your credentials into the prompts to obtain an API key")
    username = getpass.getpass(prompt="Username: ")
    password = getpass.getpass(prompt="Password: ")
    panorama = getpass.getpass(prompt="Panorama Hostname: ")
    api_key = pan_api.get_API_key(panorama, username, password)
    with open(output, 'w') as fh:
        fh.write(api_key)
    print(f"Successfully obtained an API key and stored it to {output}")
    return api_key
