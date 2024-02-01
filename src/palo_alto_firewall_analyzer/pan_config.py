"""
Collection of functions related to working the the Palo Alto Firewall's
configuration file. The idea is that instead of making many API requests,
download the XML configuration file once and retrieve the values from there.
"""

import collections
import functools
import logging
import xml.etree.ElementTree

logger = logging.getLogger(__name__)


class PanConfig:
    """
    Represents a configuration file downloaded from a Panorama
    with the 'show config' command.
    'show config' is used instead of `export configuration` so that
    the xpath's used for retrieving values from the config
     will be the same as those used with the XML API.
    """

    def __init__(self, configdata: str, from_file=False):
        if from_file:
            # fake_response = xml.etree.ElementTree.Element('response')
            conf = xml.etree.ElementTree.fromstring(configdata)
            fake_result = xml.etree.ElementTree.Element('result')
            fake_result.append(conf)
            # fake_response.append(fake_result)
            self.configroot = fake_result
            self.config_xml = {"version": conf.get("version"),"urldb": conf.get("urldb"),"detail-version":conf.get("detail-version")}                        
        else:
            self.configroot = xml.etree.ElementTree.fromstring(configdata).find('./result')

    @functools.lru_cache(maxsize=None)
    def get_device_groups(self):
        xpath = "./config/readonly/devices/entry[@name='localhost.localdomain']/device-group/entry"
        device_groups = [elem.get('name') for elem in self.configroot.findall(xpath)]
        return device_groups

    @functools.lru_cache(maxsize=None)
    def get_device_groups_hierarchy(self):
        xpath = "./config/readonly/devices/entry[@name='localhost.localdomain']/device-group/entry"

        device_group_hierarchy_children = collections.defaultdict(list)
        device_group_hierarchy_parent = {}
        for devicegroup_elem in self.configroot.findall(xpath):
            name = devicegroup_elem.get('name')
            parent = devicegroup_elem.find('parent-dg')
            if parent is not None:
                device_group_hierarchy_children[parent.text].append(name)
                device_group_hierarchy_parent[name] = parent.text

        # The Device Group with no parents must be the root Device Group
        dg_without_parents = list(set(device_group_hierarchy_children.keys()) - set(device_group_hierarchy_parent.keys()))
        if dg_without_parents:
            device_group_hierarchy_children['shared'] = [dg_without_parents[0]]
            device_group_hierarchy_parent[dg_without_parents[0]] = 'shared'
        else:
            # Only one device group in use. Just reference it directly:
            device_group_hierarchy_children['shared'] = [name]
            device_group_hierarchy_parent[name] = 'shared'

        return device_group_hierarchy_children, device_group_hierarchy_parent

    SUPPORTED_LOCATION_TYPES = {
        'shared': "./config/shared/",
        'device-group': "./config/devices/entry/device-group/entry[@name='{device_group}']/"
    }

    SUPPORTED_POLICY_TYPES = {
        "SecurityPreRules": "pre-rulebase/security/rules/",
        "SecurityPostRules": "post-rulebase/security/rules/",
        "NATPreRules": "pre-rulebase/nat/rules/",
        "NATPostRules": "post-rulebase/nat/rules/",
        "QoSPreRules": "pre-rulebase/qos/rules/",
        "QoSPostRules": "post-rulebase/qos/rules/",
        "PolicyBasedForwardingPreRules": "pre-rulebase/pbf/rules/",
        "PolicyBasedForwardingPostRules": "post-rulebase/pbf/rules/",
        "DecryptionPreRules": "pre-rulebase/decryption/rules/",
        "DecryptionPostRules": "post-rulebase/decryption/rules/",
        "TunnelInspectionPreRules": "pre-rulebase/tunnel-inspect/rules/",
        "TunnelInspectionPostRules": "post-rulebase/tunnel-inspect/rules/",
        "ApplicationOverridePreRules": "pre-rulebase/application-override/rules/",
        "ApplicationOverridePostRules": "post-rulebase/application-override/rules/",
        "AuthenticationPreRules": "pre-rulebase/application-override/rules/",
        "AuthenticationPostRules": "post-rulebase/application-override/rules/",
        "DoSPreRules": "pre-rulebase/dos/rules/",
        "DoSPostRules": "post-rulebase/dos/rules/",
        # "SDWANPreRules":
        # "SDWANPostRules"
    }

    SUPPORTED_OBJECT_TYPES = {
        "Addresses": "address/",
        "AddressGroups": "address-group/",
        # "Regions",
        # "DynamicUserGroups",
        "Applications": "application/",
        "ApplicationGroups": "application-group/",
        # "ApplicationFilters",
        "Services": "service/",
        "ServiceGroups": "service-group/",
        # "Tags",
        # "GlobalProtectHIPObjects",
        # "GlobalProtectHIPProfiles",
        # "ExternalDynamicLists",
        # "CustomDataPatterns",
        # "CustomSpywareSignatures",
        # "CustomVulnerabilitySignatures",
        # "CustomURLCategories",
        "AntivirusSecurityProfiles": "profiles/virus/",
        # "AntiSpywareSecurityProfiles",
        # "VulnerabilityProtectionSecurityProfiles",
        # "URLFilteringSecurityProfiles",
        # "FileBlockingSecurityProfiles",
        # "WildFireAnalysisSecurityProfiles",
        # "DataFilteringSecurityProfiles",
        # "DoSProtectionSecurityProfiles",
        # "GTPProtectionSecurityProfiles",
        # "SCTPProtectionSecurityProfiles",
        "SecurityProfileGroups": "profile-group/",
        "LogForwardingProfiles": "log-settings/",
        # "AuthenticationEnforcements",
        # "DecryptionProfiles",
        # "DecryptionForwardingProfiles",
        # "SDWANPathQualityProfiles",
        # "SDWANTrafficDistributionProfiles",
        # "Schedules",
    }

    @functools.lru_cache(maxsize=None)
    def get_devicegroup_policy(self, policy_type, device_group):
        if policy_type not in self.SUPPORTED_POLICY_TYPES:
            raise Exception(
                f"Invalid policy_type '{policy_type}' ! policy_type must be one of {self.SUPPORTED_POLICY_TYPES.keys()}")

        # 'shared' is a reserved name by PA and not allowed to be used as a device group name
        if device_group == 'shared':
            location_type = 'shared'
        else:
            location_type = 'device-group'
        assert location_type in self.SUPPORTED_LOCATION_TYPES
        xpath_location_prefix = self.SUPPORTED_LOCATION_TYPES[location_type].format(device_group=device_group)
        xpath = xpath_location_prefix + self.SUPPORTED_POLICY_TYPES[policy_type]
        return self.configroot.findall(xpath)

    @functools.lru_cache(maxsize=None)
    def get_devicegroup_object(self, object_type, device_group):
        '''Returns the objects in a specific device group'''
        if object_type not in self.SUPPORTED_OBJECT_TYPES:
            raise Exception(
                f"Invalid object_type '{object_type}' ! object_type must be one of {self.SUPPORTED_OBJECT_TYPES.keys()}")

        # 'shared' is a reserved name by PA and not allowed to be used as a device group name
        if device_group == 'shared':
            location_type = 'shared'
        else:
            location_type = 'device-group'
        assert location_type in self.SUPPORTED_LOCATION_TYPES
        xpath_location_prefix = self.SUPPORTED_LOCATION_TYPES[location_type].format(device_group=device_group)
        xpath = xpath_location_prefix + self.SUPPORTED_OBJECT_TYPES[object_type]
        return self.configroot.findall(xpath)

    def get_devicegroup_all_objects(self, object_type, device_group):
        '''Returns all objects available to a device group including those from parent objects'''
        _, device_group_hierarchy_parent = self.get_device_groups_hierarchy()
        all_objects = []
        current_dg = device_group
        all_objects += self.get_devicegroup_object(object_type, current_dg)
        while current_dg in device_group_hierarchy_parent:
            current_dg = device_group_hierarchy_parent[current_dg]
            all_objects += self.get_devicegroup_object(object_type, current_dg)
        return all_objects

    @functools.lru_cache(maxsize=None)
    def get_major_version(self):
        # Returns in the form '10.0.0'
        full_version = self.configroot.find('.config').get('version')
        # API uses the form: '10.0'
        major_version = full_version.rsplit('.', 1)[0]
        return major_version

    @functools.lru_cache(maxsize=None)
    def get_managed_serials(self):
        # Returns a list of serial numbers of managed devices
        serial_elements = self.configroot.findall('./config/mgt-config/devices/entry')
        serials = [serial_element.get('name') for serial_element in serial_elements]
        return serials


def main():
    fname = "config_pretty.xml"
    with open(fname) as fh:
        data = fh.read()
        pc = PanConfig(data)
    device_groups = pc.get_device_groups()
    logger.info(device_groups)
    logger.info(pc.get_device_groups_hierarchy())

    for dg in device_groups + ['shared']:
        logger.info(dg, pc.get_devicegroup_policy('SecurityPreRules', dg))

    logger.info("Address Groups")
    logger.info(dg, pc.get_devicegroup_object('AddressGroups', 'shared'))

    global indent
    indent = 0

    def printRecur(root):
        """Recursively logger.infos the tree."""
        global indent
        logger.info(' ' * indent + '%s: %s' % (root.tag.title(), root.attrib.get('name', root.text)))
        indent += 4
        for elem in root.getchildren():
            printRecur(elem)
        indent -= 4

    printRecur(pc.get_devicegroup_object('AddressGroups', 'shared')[0])


if __name__ == "__main__":
    main()
