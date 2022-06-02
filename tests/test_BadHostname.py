#!/usr/bin/env python
import unittest
from unittest.mock import patch

from palo_alto_firewall_analyzer.core import get_policy_validators
from palo_alto_firewall_analyzer.core import ProfilePackage, ConfigurationSettings
from palo_alto_firewall_analyzer.pan_config import PanConfig


class TestBadHostname(unittest.TestCase):
    @staticmethod
    def create_profilepackage(addresses, address_groups, rules, ignored_dns_prefixes):
        device_groups = ["shared"]
        devicegroup_objects = {"shared": {}}
        devicegroup_objects["shared"]['Addresses'] = addresses
        devicegroup_objects["shared"]['AddressGroups'] = address_groups
        devicegroup_exclusive_objects = {'shared': {'SecurityPreRules': rules, 'SecurityPostRules': []}}
        settings = ConfigurationSettings().get_config()
        settings['Ignored DNS Prefixes'] = ",".join(ignored_dns_prefixes)

        profilepackage = ProfilePackage(
            api_key='',
            pan_config=PanConfig('<_/>'),
            settings=settings,
            device_group_hierarchy_children={},
            device_group_hierarchy_parent={},
            device_groups_and_firewalls={},
            device_groups=device_groups,
            devicegroup_objects=devicegroup_objects,
            devicegroup_exclusive_objects=devicegroup_exclusive_objects,
            rule_limit_enabled=False,
            no_api=False
        )
        return profilepackage

    @patch('palo_alto_firewall_analyzer.validators.bad_hostnames.cached_dns_lookup')
    def test_badhostname(self, mocked_dns_lookup):
        test_xml = """\
        <response status="success"><result><config>
          <shared>
            <pre-rulebase><security><rules>
              <entry name="test_rule">
                <source><member>invalid_fqdn</member></source>
                <destination><member>ignored_fqdn</member></destination>
              </entry>
            </rules></security></pre-rulebase>
            <address>
              <entry name="ignored_ip_netmask"><ip-netmask>127.0.0.1</ip-netmask></entry>
              <entry name="ignored_fqdn"><fqdn>ignored.tld</fqdn></entry>
              <entry name="valid_fqdn"><fqdn>valid.tld</fqdn></entry>
              <entry name="invalid_fqdn"><fqdn>invalid.bad.tld</fqdn></entry>
            </address>
            <address-group>
              <entry name="Sample valid AG"><static><member>valid_fqdn</member></static></entry>
              <entry name="Sample invalid AG"><static><member>invalid_fqdn</member></static></entry>
            </address-group>
          </shared>
        </config></result></response>
        """
        pan_config = PanConfig(test_xml)
        addresses = pan_config.get_devicegroup_object('Addresses', 'shared')
        address_groups = pan_config.get_devicegroup_object('AddressGroups', 'shared')
        rules = pan_config.get_devicegroup_policy('SecurityPreRules', 'shared')
        ignored_dns_prefixes = ["ignored"]
        mocked_dns_lookup.side_effect = ['127.0.0.1', None]
        profilepackage = self.create_profilepackage(addresses, address_groups, rules, ignored_dns_prefixes)

        _, _, validator_function = get_policy_validators()['BadHostname']
        results = validator_function(profilepackage)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].data.get('name'), 'invalid_fqdn')


    @patch('palo_alto_firewall_analyzer.validators.bad_hostnames.cached_dns_lookup')
    def test_badhostnameusage(self, mocked_dns_lookup):
        test_xml = """\
        <response status="success"><result><config>
          <shared>
            <pre-rulebase><security><rules>
              <entry name="test_rule">
                <source><member>invalid_fqdn</member></source>
                <destination><member>ignored_fqdn</member></destination>
              </entry>
            </rules></security></pre-rulebase>
            <address>
              <entry name="ignored_ip_netmask"><ip-netmask>127.0.0.1</ip-netmask></entry>
              <entry name="ignored_fqdn"><fqdn>ignored.tld</fqdn></entry>
              <entry name="valid_fqdn"><fqdn>valid.tld</fqdn></entry>
              <entry name="invalid_fqdn"><fqdn>invalid.bad.tld</fqdn></entry>
            </address>
            <address-group>
              <entry name="Sample valid AG"><static><member>valid_fqdn</member></static></entry>
              <entry name="Sample invalid AG"><static><member>invalid_fqdn</member></static></entry>
            </address-group>
          </shared>
        </config></result></response>
        """
        pan_config = PanConfig(test_xml)
        addresses = pan_config.get_devicegroup_object('Addresses', 'shared')
        address_groups = pan_config.get_devicegroup_object('AddressGroups', 'shared')
        rules = pan_config.get_devicegroup_policy('SecurityPreRules', 'shared')
        ignored_dns_prefixes = ["ignored"]
        mocked_dns_lookup.side_effect = ['127.0.0.1', None]
        profilepackage = self.create_profilepackage(addresses, address_groups, rules, ignored_dns_prefixes)

        _, _, validator_function = get_policy_validators()['BadHostnameUsage']
        results = validator_function(profilepackage)
        self.assertEqual(len(results), 2)
        self.assertEqual(results[0].data.get('name'), 'Sample invalid AG')
        self.assertEqual(results[1].data.get('name'), 'test_rule')

if __name__ == "__main__":
    unittest.main()
