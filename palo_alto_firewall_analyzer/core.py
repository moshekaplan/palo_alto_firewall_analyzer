import collections
import dataclasses
import functools
import ipaddress
import socket
import xml.etree.ElementTree

import typing
import xmltodict

from palo_alto_firewall_analyzer.pan_config import PanConfig

# A registry is used to auto-register the policy validators and fixers.
policy_validator_registry = {}


def register_policy_validator(readable_name, description):
    def inner_decorator(f):
        if readable_name in policy_validator_registry:
            raise KeyError(f"Name '{readable_name}' already in use!")
        policy_validator_registry[readable_name] = (readable_name, description, f)
        return f

    return inner_decorator


def get_policy_validators():
    return policy_validator_registry


policy_fixer_registry = {}


def register_policy_fixer(readable_name, description):
    def inner_decorator(f):
        if readable_name in policy_fixer_registry:
            raise KeyError(f"Name '{readable_name}' already in use!")
        policy_fixer_registry[readable_name] = (readable_name, description, f)
        return f

    return inner_decorator


def get_policy_fixers():
    return policy_fixer_registry


@dataclasses.dataclass
class ProfilePackage:
    """Class for storing the values associated with a firewall configuration"""
    panorama: str
    api_key: str
    pan_config: PanConfig
    mandated_log_profile: str
    allowed_group_profiles: typing.List[str]
    default_group_profile: str
    ignored_dns_prefixes: typing.List[str]
    device_group_hierarchy_children: typing.Dict[str, typing.List]
    device_group_hierarchy_parent: typing.Dict[str, str]
    device_groups_and_firewalls: typing.Dict[str, typing.List[str]]
    device_groups: typing.List[str]
    devicegroup_objects: typing.Dict
    devicegroup_exclusive_objects: typing.Dict
    rule_limit_enabled: bool
    verbose: bool
    no_api: bool


BadEntry = collections.namedtuple('BadEntry', ['data', 'text', 'device_group', 'entry_type'])


@functools.lru_cache(maxsize=None)
def cached_dns_lookup(domain):
    try:
        return socket.gethostbyname(domain)
    except socket.gaierror:
        return None


def get_single_ip_from_address(address_entry):
    """
    address_entry: Address object
    Return: An ip address that is inside of the Address Object.
    """
    if "ip-netmask" in address_entry:
        return ipaddress.ip_network(address_entry['ip-netmask'], False)[0].exploded
    elif 'ip-range' in address_entry:
        return address_entry['ip-range'].split('-', 1)[0]
    elif 'fqdn' in address_entry:
        ip = cached_dns_lookup(address_entry['fqdn'])
        if ip:
            return ip
    else:
        # wildcard masks aren't supported yet
        raise Exception(f"Unable to extract an ip from {address_entry}")


@functools.lru_cache(maxsize=None)
def xml_object_to_dict(xml_obj):
    obj_xml_string = xml.etree.ElementTree.tostring(xml_obj)
    obj_dict = xmltodict.parse(obj_xml_string)
    return obj_dict


@functools.lru_cache(maxsize=None)
def get_single_ip_from_address(address_entry):
    """
    address_entry: Address object
    Return: An ip address that is inside of the Address Object.
    """

    address_dict = xml_object_to_dict(address_entry)['entry']

    if "ip-netmask" in address_dict:
        return ipaddress.ip_network(address_dict['ip-netmask'], False)[0].exploded
    elif 'ip-range' in address_dict:
        return address_dict['ip-range'].split('-', 1)[0]
    elif 'fqdn' in address_dict:
        ip = cached_dns_lookup(address_dict['fqdn'])
        if ip:
            return ip
    else:
        # wildcard masks aren't supported yet
        raise Exception(f"Unable to extract an ip from {address_entry}")


def _squash_devicegroup(device_group, device_group_hierarchy_children):
    """Recursive function for determining all of a device group's child device groups"""
    result = [device_group]
    if device_group in device_group_hierarchy_children:
        for child_dg in device_group_hierarchy_children[device_group]:
            result += _squash_devicegroup(child_dg, device_group_hierarchy_children)
    return sorted(result)


def squash_all_devicegroups(device_groups_and_firewalls, device_group_hierarchy_children,
                            device_group_hierarchy_parent):
    """Squashes all device groups, so that a single device group can be mapped to all child Device Groups
    This is useful for when seeing which device groups rules at a higher-level device group apply to"""
    all_devicegroups = {}
    for device_group in device_groups_and_firewalls.keys():
        all_devicegroups[device_group] = _squash_devicegroup(device_group, device_group_hierarchy_children)
    return all_devicegroups
