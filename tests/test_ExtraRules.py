#!/usr/bin/env python
import collections
import unittest
from unittest.mock import patch

from palo_alto_firewall_analyzer.core import ProfilePackage
from palo_alto_firewall_analyzer.pan_config import PanConfig
from palo_alto_firewall_analyzer.validators.zone_based_checks import find_extra_rules


class TestExtraRules(unittest.TestCase):
    @staticmethod
    def create_profilepackage(rules, addresses):
        device_groups = ['test_dg']
        devicegroup_objects = {'test_dg': collections.defaultdict(list)}
        devicegroup_objects['test_dg']['Addresses'] = addresses
        devicegroup_objects['test_dg']['all_active_child_firewalls'] = ["fake_firewall"]
        devicegroup_exclusive_objects = {'test_dg': collections.defaultdict(list)}
        devicegroup_exclusive_objects["test_dg"]['SecurityPreRules'] = rules

        profilepackage = ProfilePackage(
            panorama='',
            version='',
            api_key='',
            pan_config=PanConfig('<_/>'),
            mandated_log_profile='',
            allowed_group_profiles=[],
            default_group_profile='',
            ignored_dns_prefixes=[],
            device_group_hierarchy_children={},
            device_group_hierarchy_parent={},
            device_groups_and_firewalls={},
            device_groups=device_groups,
            devicegroup_objects=devicegroup_objects,
            devicegroup_exclusive_objects=devicegroup_exclusive_objects,
            rule_limit_enabled=False,
            verbose=False
        )
        return profilepackage

    @patch('palo_alto_firewall_analyzer.validators.zone_based_checks.get_firewall_zone')
    def test_with_mandated_profile(self, get_firewall_zone):
        test_xml = """\
        <response status="success"><result><config>
          <devices><entry><device-group><entry name="test_dg">
            <pre-rulebase><security><rules>
              <entry name="same_zone_rule">
                <from>
                  <member>src_zone</member>
                </from>
                <to>
                  <member>dest_zone</member>
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
        rules = pan_config.get_devicegroup_policy('SecurityPreRules', 'device-group', 'test_dg')
        addresses = pan_config.get_devicegroup_object('Addresses', 'device-group', 'test_dg')

        profilepackage = self.create_profilepackage(rules, addresses)
        get_firewall_zone.side_effect = ['src_zone', 'src_zone']
        results = find_extra_rules(profilepackage)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].data.get('name'), 'same_zone_rule')


if __name__ == "__main__":
    unittest.main()
