#!/usr/bin/env python
import collections
import unittest

from palo_alto_firewall_analyzer.core import get_policy_validators
from palo_alto_firewall_analyzer.core import ProfilePackage, ConfigurationSettings
from palo_alto_firewall_analyzer.pan_config import PanConfig


class TestFindConsolidatableServicesAndGroups(unittest.TestCase):
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
            rule_limit_enabled=False
        )
        return profilepackage

    def test_equivalent_services(self):
        test_xml = """\
        <response status="success"><result><config>
          <shared>
            <service>
              <entry name="tcp1-nondup1"><protocol><tcp><port>1</port><override><no/></override></tcp></protocol></entry>
              <entry name="tcp2-dup1"><protocol><tcp><port>2</port><override><no/></override></tcp></protocol></entry>
              <entry name="tcp2-dup2"><protocol><tcp><port>2</port><override><no/></override></tcp></protocol></entry>
            </service>
          </shared>
          <devices><entry><device-group><entry name="test_dg">
            <service>
              <entry name="tcp1-nondup2"><protocol><tcp><port>1</port><override><yes/></override></tcp></protocol></entry>
            </service>
          </entry></device-group></entry></devices>
          <devices><entry><device-group><entry name="test_dg">
            <pre-rulebase><security><rules>
              <entry name="rule1">
                <from><member>src_zone</member></from>
                <to><member>dest_zone</member></to>
                <source><member>ip-127.0.0.2</member></source>
                <destination><member>ip-127.0.0.3</member></destination>
                <service><member>tcp2-dup1</member></service>
              </entry>
              <entry name="rule2">
                <from><member>src_zone</member></from>
                <to><member>dest_zone</member></to>
                <source><member>ip-127.0.0.2</member></source>
                <destination><member>ip-127.0.0.3</member></destination>
                <service><member>tcp2-dup1</member></service>
              </entry>
              <entry name="rule3">
                <from><member>src_zone</member></from>
                <to><member>dest_zone</member></to>
                <source><member>ip-127.0.0.2</member></source>
                <destination><member>ip-127.0.0.3</member></destination>
                <service><member>tcp2-dup2</member></service>
              </entry>
            </rules></security></pre-rulebase>
            <address>
              <entry name="ip-127.0.0.2"><ip-netmask>127.0.0.2</ip-netmask></entry>
              <entry name="ip-127.0.0.3"><ip-netmask>127.0.0.3</ip-netmask></entry>
            </address>
          </entry></device-group></entry></devices>
        </config></result></response>
        """
        pan_config = PanConfig(test_xml)
        profilepackage = self.create_profilepackage(pan_config)

        _, _, validator_function = get_policy_validators()['FindConsolidatableServices']
        results, count_checks = validator_function(profilepackage)
        self.assertEqual(len(results), 1)
        self.assertEqual(count_checks, 1)
        self.assertEqual(len(results[0].data), 2)

        self.assertEqual(results[0].data[0].get('name'), 'rule3')
        self.assertEqual(results[0].data[1]['service']['member'], 'tcp2-dup1')

    def test_equivalent_servicegroups(self):
        test_xml = """\
        <response status="success"><result><config>
          <shared>
            <service-group>
              <entry name="sg-dup1"><members><member>tcp-1</member></members></entry>
              <entry name="sg-dup2"><members><member>tcp-1</member></members></entry>
              <entry name="sg-nondup3"><members><member>tcp-2</member></members></entry>
            </service-group>
            <service>
              <entry name="tcp1"><protocol><tcp><port>1</port><override><no/></override></tcp></protocol></entry>
              <entry name="tcp2"><protocol><tcp><port>2</port><override><no/></override></tcp></protocol></entry>
            </service>
          </shared>
          <devices><entry><device-group><entry name="test_dg">
            <service>
              <entry name="tcp1-nondup2"><protocol><tcp><port>1</port><override><yes/></override></tcp></protocol></entry>
            </service>
          </entry></device-group></entry></devices>
          <devices><entry><device-group><entry name="test_dg">
            <pre-rulebase><security><rules>
              <entry name="rule1">
                <from><member>src_zone</member></from>
                <to><member>dest_zone</member></to>
                <source><member>ip-127.0.0.2</member></source>
                <destination><member>ip-127.0.0.3</member></destination>
                <service><member>sg-dup1</member></service>
              </entry>
              <entry name="rule2">
                <from><member>src_zone</member></from>
                <to><member>dest_zone</member></to>
                <source><member>ip-127.0.0.2</member></source>
                <destination><member>ip-127.0.0.3</member></destination>
                <service><member>sg-dup1</member></service>
              </entry>
              <entry name="rule3">
                <from><member>src_zone</member></from>
                <to><member>dest_zone</member></to>
                <source><member>ip-127.0.0.2</member></source>
                <destination><member>ip-127.0.0.3</member></destination>
                <service><member>sg-dup2</member></service>
              </entry>
            </rules></security></pre-rulebase>
            <address>
              <entry name="ip-127.0.0.2"><ip-netmask>127.0.0.2</ip-netmask></entry>
              <entry name="ip-127.0.0.3"><ip-netmask>127.0.0.3</ip-netmask></entry>
            </address>
          </entry></device-group></entry></devices>
        </config></result></response>
        """
        pan_config = PanConfig(test_xml)
        profilepackage = self.create_profilepackage(pan_config)

        _, _, validator_function = get_policy_validators()['FindConsolidatableServiceGroups']
        results, count_checks = validator_function(profilepackage)
        self.assertEqual(len(results), 1)
        self.assertEqual(count_checks, 1)
        self.assertEqual(len(results[0].data), 2)

        self.assertEqual(results[0].data[0].get('name'), 'rule3')
        self.assertEqual(results[0].data[1]['service']['member'], 'sg-dup1')



if __name__ == "__main__":
    unittest.main()
