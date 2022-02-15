#!/usr/bin/env python
import collections
import unittest

from palo_alto_firewall_analyzer.core import get_policy_validators
from palo_alto_firewall_analyzer.core import ProfilePackage, ConfigurationSettings
from palo_alto_firewall_analyzer.pan_config import PanConfig


class TestFindConsolidatableAddressesAndGroups(unittest.TestCase):
    @staticmethod
    def create_profilepackage(pan_config):
        device_groups = ["shared", "test_dg"]
        device_group_hierarchy_parent = {"test_dg": "shared"}
        devicegroup_objects = {"shared": collections.defaultdict(list), "test_dg": collections.defaultdict(list)}
        devicegroup_objects['shared']['all_child_device_groups'] = ["shared", "test_dg"]

        profilepackage = ProfilePackage(
            api_key='',
            pan_config=pan_config,
            settings=ConfigurationSettings().get_config(),
            device_group_hierarchy_children={},
            device_group_hierarchy_parent=device_group_hierarchy_parent,
            device_groups_and_firewalls={},
            device_groups=device_groups,
            devicegroup_objects=devicegroup_objects,
            devicegroup_exclusive_objects={},
            rule_limit_enabled=False,
            verbose=False,
            no_api=False
        )
        return profilepackage

    def test_consolidatable_addresses(self):
        test_xml = """\
        <response status="success"><result><config>
          <shared>
            <address>
              <entry name="unique_netmask1"><ip-netmask>127.0.0.1/32</ip-netmask></entry>
              <entry name="unique_netmask2"><ip-netmask>127.0.0.2/32</ip-netmask></entry>
              <entry name="duplicate_netmask2"><ip-netmask>127.0.0.2/32</ip-netmask></entry>
            </address>
            <address-group>
              <entry name="address_group1"><static><member>unique_netmask1</member><member>unique_netmask2</member></static></entry>
              <entry name="address_group2"><static><member>unique_netmask2</member><member>unique_netmask1</member></static></entry>
              <entry name="address_group3"><static><member>duplicate_netmask2</member><member>unique_netmask1</member></static></entry>
            </address-group>
          </shared>
          <devices><entry><device-group><entry name="test_dg">
            <pre-rulebase><security><rules>
              <entry name="rule1">
                <from><member>src_zone</member></from>
                <to><member>dest_zone</member></to>
                <source><member>unique_netmask1</member></source>
                <destination><member>unique_netmask2</member></destination>
                <service><member>tcp2-dup1</member></service>
              </entry>
              <entry name="rule2">
                <from><member>src_zone</member></from>
                <to><member>dest_zone</member></to>
                <source><member>unique_netmask1</member></source>
                <destination><member>unique_netmask2</member></destination>
                <service><member>tcp2-dup1</member></service>
              </entry>
              <entry name="rule3">
                <from><member>src_zone</member></from>
                <to><member>dest_zone</member></to>
                <source><member>unique_netmask1</member></source>
                <destination><member>duplicate_netmask2</member></destination>
                <service><member>tcp2-dup2</member></service>
              </entry>
            </rules></security></pre-rulebase>
          </entry></device-group></entry></devices>
        </config></result></response>
        """
        pan_config = PanConfig(test_xml)
        profilepackage = self.create_profilepackage(pan_config)

        _, _, validator_function = get_policy_validators()['FindConsolidatableAddresses']
        results = validator_function(profilepackage)
        self.assertEqual(len(results), 2)
        self.assertEqual(len(results[0].data), 2)
        self.assertEqual(results[0].data[0].get('name'), 'address_group3')
        self.assertEqual(results[0].data[1]['static']['member'][0], 'unique_netmask2')
        self.assertEqual(len(results[1].data), 2)
        self.assertEqual(results[1].data[0].get('name'), 'rule3')
        self.assertEqual(results[1].data[1]['destination']['member'], 'unique_netmask2')

    def test_consolidatable_addressgroups(self):
        test_xml = """\
        <response status="success"><result><config>
          <shared>
            <address>
              <entry name="unique_netmask1"><ip-netmask>127.0.0.1/32</ip-netmask></entry>
              <entry name="unique_netmask2"><ip-netmask>127.0.0.2/32</ip-netmask></entry>
              <entry name="duplicate_netmask2"><ip-netmask>127.0.0.2/32</ip-netmask></entry>
            </address>
            <address-group>
              <entry name="address_group1"><static><member>unique_netmask1</member><member>unique_netmask2</member></static></entry>
              <entry name="address_group2"><static><member>unique_netmask2</member><member>unique_netmask1</member></static></entry>
              <entry name="address_group3"><static><member>duplicate_netmask2</member><member>unique_netmask1</member></static></entry>
            </address-group>
          </shared>
          <devices><entry><device-group><entry name="test_dg">
            <pre-rulebase><security><rules>
              <entry name="rule1">
                <from><member>src_zone</member></from>
                <to><member>dest_zone</member></to>
                <source><member>address_group1</member></source>
                <destination><member>unique_netmask2</member></destination>
                <service><member>tcp2-dup1</member></service>
              </entry>
              <entry name="rule2">
                <from><member>src_zone</member></from>
                <to><member>dest_zone</member></to>
                <source><member>address_group1</member></source>
                <destination><member>unique_netmask2</member></destination>
                <service><member>tcp2-dup1</member></service>
              </entry>
              <entry name="rule3">
                <from><member>src_zone</member></from>
                <to><member>dest_zone</member></to>
                <source><member>address_group2</member></source>
                <destination><member>duplicate_netmask2</member></destination>
                <service><member>tcp2-dup2</member></service>
              </entry>
            </rules></security></pre-rulebase>
          </entry></device-group></entry></devices>
        </config></result></response>
        """
        pan_config = PanConfig(test_xml)
        profilepackage = self.create_profilepackage(pan_config)

        _, _, validator_function = get_policy_validators()['FindConsolidatableAddressGroups']
        results = validator_function(profilepackage)
        self.assertEqual(len(results), 1)
        self.assertEqual(len(results[0].data), 2)
        self.assertEqual(results[0].data[0].get('name'), 'rule3')
        self.assertEqual(results[0].data[1]['source']['member'], 'address_group1')


if __name__ == "__main__":
    unittest.main()
