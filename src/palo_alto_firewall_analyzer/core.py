import collections
import configparser
import dataclasses
import functools
import ipaddress
import logging
import os
import socket
import typing
import xml.etree.ElementTree
import xmltodict

from palo_alto_firewall_analyzer.pan_config import PanConfig

logger = logging.getLogger(__name__)

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


class ConfigurationSettings:
    """
    Represents a local configuration file
    with settings for controlling the behavior
    of the validator and fixer scripts
    """

    def __init__(self, configfile=None, panorama=None):
        """Load data from a file, otherwise create
        a config object with default settings"""

        if configfile:
            logger.debug(f"Loading config file from {configfile}")
            # Validate config file exists
            if not os.path.isfile(configfile):
                raise Exception(f"Config file '{configfile}' does not exist! Exiting")
            self.local_config = configparser.ConfigParser()
            self.local_config.read(configfile)
            self.validate_mandatory_fields()
        else:
            # Otherwise generate a default config file
            self.local_config = configparser.ConfigParser(allow_no_value=True)
            self.local_config.add_section('Analyzer')
            self.local_config.set('Analyzer', '# Mandatory: The hostname of the panorama to query')
            if panorama is None:
                panorama = 'my-panorama-hostname'
            self.local_config.set('Analyzer', 'Panorama', panorama)

            self.local_config.set('Analyzer', '# Optional config values, used by validators')
            self.local_config.set('Analyzer', '# ExtraRules, ExtraZones, MissingZones: Enable validators that require making many API requests')
            self.local_config.set('Analyzer', '# Enable validators with many API requests = false')

            self.local_config.set('Analyzer', '# DisabledPolicies: Ignore the following disabled rules: (comma delimited)')
            self.local_config.set('Analyzer', '# Ignored Disabled Policies = Rule 1,Rule 2')

            self.local_config.set('Analyzer', '# Mandate a specific log profile')
            self.local_config.set('Analyzer', '# Mandated Logging Profile = default')

            self.local_config.set('Analyzer', '# Ignore certain DNS prefixes in find_badhostname, as they might not always be available (e.g., DHCP)')
            self.local_config.set('Analyzer', '# Ignored DNS Prefixes = PC-,iPhone')

            self.local_config.set('Analyzer', '# Specify which Security Profile Groups are allowed and the default profile')
            self.local_config.set('Analyzer', '# Allowed Group Profiles = Security Profile Group-default,Security Profile Group-1,Security Profile Group-2')
            self.local_config.set('Analyzer', '# Default Group Profile = Security Profile Group-default')

            self.local_config.set('Analyzer', '# UnconventionallyNamedAddresses: Specify a format for Address object names. Available fields are: {host}, {network}, {range}, {fqdn}, {mask}')
            self.local_config.set('Analyzer', '# host is for an IPv4 with a /32 netmask, IPv6 with a /128, or a host without a netmask at all')
            self.local_config.set('Analyzer', 'fqdn name format = fqdn-{fqdn}')
            self.local_config.set('Analyzer', 'host name format = host-{host}')
            self.local_config.set('Analyzer', 'net name format = net-{host}_{network}')
            self.local_config.set('Analyzer', 'range name format = range-{range}')
            self.local_config.set('Analyzer', '# Palo alto does not allow colon (:) characters in names')
            self.local_config.set('Analyzer', 'ipv6 colon replacement char = _')
            self.local_config.set('Analyzer', 'wildcard name format = wildcard-{mask}')

            self.local_config.set('Analyzer', '# UnconventionallyNamedServices: Specify a format for Service object names. Available fields are: {transport}, {source-port}, {port}, {override}')
            self.local_config.set('Analyzer', '# service name format = {transport}-{port}')

            self.local_config.set('Analyzer', '# EquivalentObjects: Whether to ignore the description field when comparing if two objects are equivalent (false by default)')
            self.local_config.set('Analyzer', 'Equivalent objects ignore description = false')
            self.local_config.set('Analyzer', 'Equivalent objects ignore tags = false')

    def validate_mandatory_fields(self):
        panorama = self.local_config['Analyzer']['Panorama']
        if not panorama:
            raise Exception("Panorama needs to be specified!")

    def write_config(self, config_path):
        os.makedirs(os.path.dirname(config_path), exist_ok=True)
        with open(config_path, 'w') as config_fh:
            self.local_config.write(config_fh)

    def get_config(self):
        return self.local_config['Analyzer']


@dataclasses.dataclass
class ProfilePackage:
    """Class for storing the values associated with a firewall configuration"""
    api_key: str
    pan_config: PanConfig
    settings: ConfigurationSettings
    device_group_hierarchy_children: typing.Dict[str, typing.List]
    device_group_hierarchy_parent: typing.Dict[str, str]
    device_groups_and_firewalls: typing.Dict[str, typing.List[str]]
    device_groups: typing.List[str]
    devicegroup_objects: typing.Dict
    devicegroup_exclusive_objects: typing.Dict
    rule_limit_enabled: bool

Detail = collections.namedtuple('Detail',['policy_type','policy_name','device_group',
                                          'entry_type','entry_name','entry_value',
                                          'rule_type','rule_name','protocol',
                                          'port','allowed_group_profiles','group_profile_setting','address',
                                          'fqdn','ip','ip_mask','loc','mandated_log_profile','log_setting',
                                          'object_entry_name','policy_entry_name','shadowing_address_name',
                                          'zone_type','zones','extra'
                                          ]
                                )
BadEntry = collections.namedtuple('BadEntry', ['data', 'text', 'device_group', 'entry_type','Detail'])

@functools.lru_cache(maxsize=None)
def cached_dns_lookup(domain):
    try:
        result = socket.gethostbyname(domain)
        logger.debug(f"gethostbyname() Domain:{domain} resolved to:{result}")
        return result
    except socket.gaierror:
        logger.debug(f"gethostbyname() Domain:{domain} failed to resolve")
        return None


@functools.lru_cache(maxsize=None)
def cached_dns_ex_lookup(domain):
    try:
        result = socket.gethostbyname_ex(domain)
        logger.debug(f"gethostbyname_ex() - Domain:{domain} resolved to:{result}")
        return result
    except socket.gaierror:
        logger.debug(f"gethostbyname_ex() Domain:{domain} failed to resolve")
        return (None, [], [])


@functools.lru_cache(maxsize=None)
def cached_fqdn_lookup(domain):
    try:
        result = socket.getfqdn(domain)
        logger.debug(f"getfqdn() - Domain:{domain} resolved to:{result}")
        return result
    except socket.gaierror:
        logger.debug(f"getfqdn() Domain:{domain} failed to resolve")
        return None


@functools.lru_cache(maxsize=None)
def xml_object_to_dict1(xml_obj):
    obj_xml_string = xml.etree.ElementTree.tostring(xml_obj)
    obj_dict = xmltodict.parse(obj_xml_string)
    return obj_dict

def xml_object_to_dict(xml_obj):
    obj_xml_string = xml.etree.ElementTree.tostring(xml_obj) 
    
    root = xml.etree.ElementTree.fromstring(obj_xml_string)    
    
    list_atr_remove = ['loc']
    
    def remove_loc(elements,atr):
        if atr in elements.attrib:
            del elements.attrib[atr]
        for elem in elements:
            remove_loc(elem,atr)
    
    for atr in list_atr_remove:    
        for entry in root:        
            remove_loc(entry,atr)    
    
    xml_atr_remove = xml.etree.ElementTree.tostring(root)
            
    obj_dict = xmltodict.parse(xml_atr_remove)    
    
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


def squash_all_devicegroups(device_groups, device_group_hierarchy_children):
    """Squashes all device groups, so that a single device group can be mapped to all child Device Groups
    This is useful for when seeing which device groups rules at a higher-level device group apply to"""
    all_devicegroups = {}
    for device_group in device_groups:
        all_devicegroups[device_group] = _squash_devicegroup(device_group, device_group_hierarchy_children)
    return all_devicegroups
