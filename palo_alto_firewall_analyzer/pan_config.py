"""
Collection of functions related to working the the Palo Alto Firewall's
configuration file. The idea is that instead of making many API requests,
download the XML configuration file once and retrieve the values from there.
"""

import xml.etree.ElementTree
import functools
import collections


class PanConfig:
    """
    Represents a configuration file downloaded from a Panorama
    with the 'show config' command.
    'show config' is used instead of `export configuration` so that
    the xpath's used for retrieving values from the config
     will be the same as those used with the XML API.
    """

    def __init__(self, configdata: str):
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

        # The Device Group with a child and no parents must be the root Device Group
        shared_child = list(set(device_group_hierarchy_children.keys()) - set(device_group_hierarchy_parent.keys()))[0]
        device_group_hierarchy_children['shared'] = [shared_child]
        device_group_hierarchy_parent[shared_child] = 'shared'

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
        "TunnelInspectionPreRules": "pre-rulebase/tunnel-inspect/rules",
        "TunnelInspectionPostRules": "post-rulebase/tunnel-inspect/rules/",
        "ApplicationOverridePreRules": "pre-rulebase/application-override/rules",
        "ApplicationOverridePostRules": "post-rulebase/application-override/rules/",
        "AuthenticationPreRules": "pre-rulebase/application-override/rules",
        "AuthenticationPostRules": "post-rulebase/application-override/rules/",
        "DoSPreRules": "pre-rulebase/dos/rules",
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
        # "SecurityProfileGroups",
        "LogForwardingProfiles": "log-settings/",
        # "AuthenticationEnforcements",
        # "DecryptionProfiles",
        # "DecryptionForwardingProfiles",
        # "SDWANPathQualityProfiles",
        # "SDWANTrafficDistributionProfiles",
        # "Schedules",
    }

    @functools.lru_cache(maxsize=None)
    def get_devicegroup_policy(self, policytype, locationtype, device_group=None):
        if locationtype not in self.SUPPORTED_LOCATION_TYPES:
            raise Exception(
                f"Unsupported locationtype of {locationtype}! locationtype must be one of {self.SUPPORTED_LOCATION_TYPES.keys()}")

        if policytype not in self.SUPPORTED_POLICY_TYPES:
            raise Exception(
                f"Invalid policytype '{policytype}' ! policytype must be one of {self.SUPPORTED_POLICY_TYPES.keys()}")

        xpath_location_prefix = self.SUPPORTED_LOCATION_TYPES[locationtype].format(device_group=device_group)
        xpath = xpath_location_prefix + self.SUPPORTED_POLICY_TYPES[policytype]
        return self.configroot.findall(xpath)

    @functools.lru_cache(maxsize=None)
    def get_devicegroup_object(self, object_type, location_type, device_group=None):
        if location_type not in self.SUPPORTED_LOCATION_TYPES:
            raise Exception(
                f"Unsupported locationtype of {location_type}! locationtype must be one of {self.SUPPORTED_LOCATION_TYPES.keys()}")

        if object_type not in self.SUPPORTED_OBJECT_TYPES:
            raise Exception(
                f"Invalid policytype '{object_type}' ! object_type must be one of {self.SUPPORTED_OBJECT_TYPES.keys()}")

        xpath_location_prefix = self.SUPPORTED_LOCATION_TYPES[location_type].format(device_group=device_group)
        xpath = xpath_location_prefix + self.SUPPORTED_OBJECT_TYPES[object_type]
        return self.configroot.findall(xpath)

    @functools.lru_cache(maxsize=None)
    def get_major_version(self):
        # Returns in the form '10.0.0'
        full_version = self.configroot.find('.config').get('version')
        # API uses the form: '10.0'
        major_version = full_version.rsplit('.', 1)[0]
        return major_version

def main():
    fname = "config_pretty.xml"
    with open(fname) as fh:
        data = fh.read()
        pc = PanConfig(data)
    device_groups = pc.get_device_groups()
    print(device_groups)
    print(pc.get_device_groups_hierarchy())

    for dg in device_groups + ['shared']:
        print(dg, pc.get_devicegroup_policy('SecurityPreRules', 'device-group', dg))

    print ("Address Groups")
    print(dg, pc.get_devicegroup_object('AddressGroups', 'shared'))

    global indent
    indent = 0
    def printRecur(root):
        """Recursively prints the tree."""
        global indent
        print(' ' * indent + '%s: %s' % (root.tag.title(), root.attrib.get('name', root.text)))
        indent += 4
        for elem in root.getchildren():
            printRecur(elem)
        indent -= 4

    printRecur(pc.get_devicegroup_object('AddressGroups', 'shared')[0])


if __name__ == "__main__":
    main()
