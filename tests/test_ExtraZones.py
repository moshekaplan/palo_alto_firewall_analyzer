#!/usr/bin/env python
import collections
import unittest
from unittest.mock import patch

from palo_alto_firewall_analyzer.core import get_policy_validators
from palo_alto_firewall_analyzer.core import ProfilePackage, ConfigurationSettings
from palo_alto_firewall_analyzer.pan_config import PanConfig


class TestExtraZones(unittest.TestCase):
    @staticmethod
    def create_profilepackage(rules, addresses):
        device_groups = ['test_dg']
        devicegroup_objects = {'test_dg': collections.defaultdict(list)}
        devicegroup_objects['test_dg']['Addresses'] = addresses
        devicegroup_objects['test_dg']['all_active_child_firewalls'] = ["fake_firewall"]
        devicegroup_exclusive_objects = {'test_dg': collections.defaultdict(list)}
        devicegroup_exclusive_objects["test_dg"]['SecurityPreRules'] = rules

        settings = ConfigurationSettings().get_config()
        settings['Enable validators with many API requests'] = "true"

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
            rule_limit_enabled=False
        )
        return profilepackage

    @patch('palo_alto_firewall_analyzer.validators.zone_based_checks.get_firewall_zone')
    def test_with_extrazone(self, get_firewall_zone):
        test_xml = """\
        <response status="success"><result><config>
          <devices><entry><device-group><entry name="test_dg">
            <pre-rulebase><security><rules>
              <entry name="extra_zone_rule">
                <from>
                  <member>src_zone</member>
                </from>
                <to>
                  <member>dest_zone</member>
                  <member>dest_zone_extra</member>
                </to>
                <source>
                  <member>ip-127.0.0.2</member>
                </source>
                <destination>
                  <member>ip-127.0.0.3</member>
                </destination>
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
        rules = pan_config.get_devicegroup_policy('SecurityPreRules', 'test_dg')
        addresses = pan_config.get_devicegroup_object('Addresses', 'test_dg')

        profilepackage = self.create_profilepackage(rules, addresses)
        get_firewall_zone.side_effect = ['src_zone', 'dest_zone']
        _, _, validator_function = get_policy_validators()['ExtraZones']
        results, _ = validator_function(profilepackage)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].data.get('name'), 'extra_zone_rule')

    @patch('palo_alto_firewall_analyzer.validators.zone_based_checks.get_firewall_zone')
    def test_with_extrazone_hardcoded_ip(self, get_firewall_zone):
        test_xml = """\
        <response status="success"><result><config>
          <devices><entry><device-group><entry name="test_dg">
            <pre-rulebase><security><rules>
              <entry name="extra_zone_rule">
                <from><member>src_zone</member></from>
                <to>
                  <member>dest_zone</member>
                  <member>dest_zone_extra</member>
                </to>
                <source><member>127.0.0.2</member></source>
                <destination><member>ip-127.0.0.3</member></destination>
              </entry>
            </rules></security></pre-rulebase>
            <address><entry name="ip-127.0.0.3"><ip-netmask>127.0.0.3</ip-netmask></entry></address>
          </entry></device-group></entry></devices>
        </config></result></response>
        """
        pan_config = PanConfig(test_xml)
        rules = pan_config.get_devicegroup_policy('SecurityPreRules', 'test_dg')
        addresses = pan_config.get_devicegroup_object('Addresses', 'test_dg')

        profilepackage = self.create_profilepackage(rules, addresses)
        get_firewall_zone.side_effect = ['src_zone', 'dest_zone']
        _, _, validator_function = get_policy_validators()['ExtraZones']
        results, _ = validator_function(profilepackage)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].data.get('name'), 'extra_zone_rule')


    @patch('palo_alto_firewall_analyzer.validators.zone_based_checks.get_firewall_zone')
    def test_with_extrazone_any(self, get_firewall_zone):
        test_xml = """\
        <response status="success"><result><config>
          <devices><entry><device-group><entry name="test_dg">
            <pre-rulebase><security><rules>
              <entry name="rule_1">
                <to><member>zone_a</member></to>
                <from><member>zone_b</member></from>
                <source><member>any</member></source>
                <destination><member>any</member></destination>
                <service><member>tcp-1</member></service>
                <disabled>no</disabled>
              </entry>
            </rules></security></pre-rulebase>
          </entry></device-group></entry></devices>
        </config></result></response>
        """
        pan_config = PanConfig(test_xml)
        rules = pan_config.get_devicegroup_policy('SecurityPreRules', 'test_dg')
        addresses = pan_config.get_devicegroup_object('Addresses', 'test_dg')
        profilepackage = self.create_profilepackage(rules, addresses)
        get_firewall_zone.side_effect = ['src_zone', 'dest_zone']
        _, _, validator_function = get_policy_validators()['ExtraZones']
        results, _ = validator_function(profilepackage)
        self.assertEqual(len(results), 0)


    @patch('palo_alto_firewall_analyzer.validators.zone_based_checks.get_firewall_zone')
    def test_with_extrazone_missing(self, get_firewall_zone):
        test_xml = """\
        <response status="success"><result><config>
          <devices><entry><device-group><entry name="test_dg">
            <pre-rulebase><security><rules>
              <entry name="rule_1">
                <to><member>zone_a</member></to>
                <from><member>zone_b</member></from>
                <source><member>net-127.0.0.3/24</member></source>
                <destination><member>any</member></destination>
                <service><member>tcp-1</member></service>
                <disabled>no</disabled>
              </entry>
            </rules></security></pre-rulebase>
            <address><entry name="net-127.0.0.3/24"><ip-netmask>127.0.0.3/24</ip-netmask></entry></address>
          </entry></device-group></entry></devices>
        </config></result></response>
        """
        pan_config = PanConfig(test_xml)
        rules = pan_config.get_devicegroup_policy('SecurityPreRules', 'test_dg')
        addresses = pan_config.get_devicegroup_object('Addresses', 'test_dg')
        profilepackage = self.create_profilepackage(rules, addresses)
        get_firewall_zone.side_effect = ['src_zone', 'dest_zone']
        _, _, validator_function = get_policy_validators()['ExtraZones']
        results, count_checks = validator_function(profilepackage)
        self.assertEqual(len(results), 0)
        self.assertEqual(count_checks, 2)

if __name__ == "__main__":
    unittest.main()
