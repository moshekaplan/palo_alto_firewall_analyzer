#!/usr/bin/env python
import unittest

from palo_alto_firewall_analyzer.core import get_policy_validators
from palo_alto_firewall_analyzer.core import ProfilePackage, ConfigurationSettings
from palo_alto_firewall_analyzer.pan_config import PanConfig


class TestEquivalentObjects(unittest.TestCase):
    @staticmethod
    def create_profilepackage(object_type, pan_config):
        device_groups = ["shared", "test_dg"]
        device_group_hierarchy_parent = {"test_dg": "shared"}

        profilepackage = ProfilePackage(
            api_key='',
            pan_config=pan_config,
            settings=ConfigurationSettings().get_config(),
            device_group_hierarchy_children={},
            device_group_hierarchy_parent=device_group_hierarchy_parent,
            device_groups_and_firewalls={},
            device_groups=device_groups,
            devicegroup_objects={},
            devicegroup_exclusive_objects={},
            rule_limit_enabled=False,
            verbose=False,
            no_api=False
        )
        return profilepackage

    def test_equivalent_addresses(self):
        test_xml = """\
        <response status="success"><result><config>
          <shared>
            <address>
              <entry name="unique_netmask"><ip-netmask>ignored.tld</ip-netmask></entry>
              <entry name="dupe_netmask1"><ip-netmask>127.0.0.1</ip-netmask></entry>
              <entry name="dupe_netmask2"><ip-netmask>127.0.0.1/32</ip-netmask></entry>
              <entry name="dup_fqdn1"><fqdn>dupfqdn.tld</fqdn></entry>
              <entry name="dup_fqdn2"><fqdn>dupfqdn.tld</fqdn></entry>
            </address>
          </shared>
          <devices><entry><device-group><entry name="test_dg">
            <address>
              <entry name="unique_fqdn"><ip-netmask>unique.tld</ip-netmask></entry>
              <entry name="dup_fqdn3"><fqdn>dupfqdn.tld</fqdn></entry>
            </address>
          </entry></device-group></entry></devices>
        </config></result></response>
        """
        pan_config = PanConfig(test_xml)
        profilepackage = self.create_profilepackage('Addresses', pan_config)
        _, _, validator_function = get_policy_validators()['EquivalentAddresses']
        results = validator_function(profilepackage)
        self.assertEqual(len(results), 3)
        self.assertEqual(len(results[0].data), 2)
        self.assertEqual(results[0].data[0][0], 'shared')
        self.assertEqual(results[0].data[0][1].get('name'), 'dup_fqdn1')
        self.assertEqual(results[0].data[1][0], 'shared')
        self.assertEqual(results[0].data[1][1].get('name'), 'dup_fqdn2')
        self.assertEqual(len(results[1].data), 2)
        self.assertEqual(results[1].data[0][0], 'shared')
        self.assertEqual(results[1].data[0][1].get('name'), 'dupe_netmask1')
        self.assertEqual(results[1].data[1][0], 'shared')
        self.assertEqual(results[1].data[1][1].get('name'), 'dupe_netmask2')
        self.assertEqual(len(results[2].data), 3)
        self.assertEqual(results[2].data[0][0], 'shared')
        self.assertEqual(results[2].data[0][1].get('name'), 'dup_fqdn1')
        self.assertEqual(results[2].data[1][0], 'shared')
        self.assertEqual(results[2].data[1][1].get('name'), 'dup_fqdn2')
        self.assertEqual(results[2].data[2][0], 'test_dg')
        self.assertEqual(results[2].data[2][1].get('name'), 'dup_fqdn3')

    def test_equivalent_addressgroups(self):
        test_xml = """\
        <response status="success"><result><config>
          <shared>
            <address>
              <entry name="unique_netmask1"><ip-netmask>127.0.0.2/32</ip-netmask></entry>
              <entry name="unique_netmask2"><ip-netmask>127.0.0.1/32</ip-netmask></entry>
            </address>
            <address-group>
              <entry name="address_group1"><static><member>unique_netmask1</member><member>unique_netmask2</member></static></entry>
              <entry name="address_group2"><static><member>unique_netmask2</member><member>unique_netmask1</member></static></entry>
            </address-group>
          </shared>
        </config></result></response>
        """
        pan_config = PanConfig(test_xml)
        profilepackage = self.create_profilepackage('AddressGroups', pan_config)
        _, _, validator_function = get_policy_validators()['EquivalentAddressGroups']
        results = validator_function(profilepackage)
        self.assertEqual(len(results), 1)
        self.assertEqual(len(results[0].data), 2)
        self.assertEqual(results[0].data[0][0], 'shared')
        self.assertEqual(results[0].data[0][1].get('name'), 'address_group1')
        self.assertEqual(results[0].data[1][0], 'shared')
        self.assertEqual(results[0].data[1][1].get('name'), 'address_group2')

    def test_equivalent_services(self):
        test_xml = """\
        <response status="success"><result><config>
          <shared>
            <service>
              <entry name="tcp-nondup1"><protocol><tcp><port>1</port><override><no/></override></tcp></protocol></entry>
              <entry name="tcp-dup1"><protocol><tcp><port>2</port><override><no/></override></tcp></protocol></entry>
              <entry name="tcp-dup2"><protocol><tcp><port>2</port><override><no/></override></tcp></protocol></entry>
            </service>
          </shared>
          <devices><entry><device-group><entry name="test_dg">
            <service>
              <entry name="tcp-dup3"><protocol><tcp><port>2</port><override><no/></override></tcp></protocol></entry>
              <entry name="tcp-nondup2"><protocol><tcp><port>1</port><override><yes/></override></tcp></protocol></entry>
            </service>
          </entry></device-group></entry></devices>
        </config></result></response>
        """
        pan_config = PanConfig(test_xml)
        profilepackage = self.create_profilepackage('Services', pan_config)

        _, _, validator_function = get_policy_validators()['EquivalentServices']
        results = validator_function(profilepackage)
        self.assertEqual(len(results), 2)
        self.assertEqual(len(results[0].data), 2)
        self.assertEqual(results[0].data[0][0], 'shared')
        self.assertEqual(results[0].data[0][1].get('name'), 'tcp-dup1')
        self.assertEqual(results[0].data[1][0], 'shared')
        self.assertEqual(results[0].data[1][1].get('name'), 'tcp-dup2')
        self.assertEqual(len(results[1].data), 3)
        self.assertEqual(results[1].data[0][0], 'shared')
        self.assertEqual(results[1].data[0][1].get('name'), 'tcp-dup1')
        self.assertEqual(results[1].data[1][0], 'shared')
        self.assertEqual(results[1].data[1][1].get('name'), 'tcp-dup2')
        self.assertEqual(results[1].data[2][0], 'test_dg')
        self.assertEqual(results[1].data[2][1].get('name'), 'tcp-dup3')

    def test_equivalent_servicegroups(self):
        test_xml = """\
        <response status="success"><result><config>
          <shared>
            <service>
              <entry name="tcp-1"><protocol><tcp><port>1</port><override><no/></override></tcp></protocol></entry>
              <entry name="tcp-2"><protocol><tcp><port>2</port><override><no/></override></tcp></protocol></entry>
            </service>
            <service-group>
              <entry name="dup1"><members><member>tcp-1</member><member>tcp-2</member></members></entry>
              <entry name="dup2"><members><member>tcp-2</member><member>tcp-1</member></members></entry>
            </service-group>
          </shared>
        </config></result></response>
        """
        pan_config = PanConfig(test_xml)
        profilepackage = self.create_profilepackage('ServiceGroups', pan_config)

        _, _, validator_function = get_policy_validators()['EquivalentServiceGroups']
        results = validator_function(profilepackage)
        self.assertEqual(len(results), 1)
        self.assertEqual(len(results[0].data), 2)
        self.assertEqual(results[0].data[0][0], 'shared')
        self.assertEqual(results[0].data[0][1].get('name'), 'dup1')
        self.assertEqual(results[0].data[1][0], 'shared')
        self.assertEqual(results[0].data[1][1].get('name'), 'dup2')


if __name__ == "__main__":
    unittest.main()
