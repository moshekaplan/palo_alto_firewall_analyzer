#!/usr/bin/env python
import unittest

from palo_alto_firewall_analyzer.core import get_policy_validators
from palo_alto_firewall_analyzer.core import ProfilePackage, ConfigurationSettings
from palo_alto_firewall_analyzer.pan_config import PanConfig


class TestRedundantRuleServices(unittest.TestCase):
    @staticmethod
    def create_profilepackage(pan_config):
        device_groups = ['test_dg']

        profilepackage = ProfilePackage(
            api_key='',
            pan_config=pan_config,
            settings=ConfigurationSettings().get_config(),
            device_group_hierarchy_children={},
            device_group_hierarchy_parent={},
            device_groups_and_firewalls={},
            device_groups=device_groups,
            devicegroup_objects={},
            devicegroup_exclusive_objects={},
            rule_limit_enabled=False
        )
        return profilepackage

    def test_with_mandated_profile(self):
        test_xml = """\
        <response status="success"><result><config>
          <devices><entry><device-group><entry name="test_dg">
            <pre-rulebase><security><rules>
              <entry name="same_zone_rule">
                <service>
                  <member>tcp-123</member>
                  <member>myservicegroup</member>
                </service>
              </entry>
            </rules></security></pre-rulebase>
            <service><entry name="tcp-123"><protocol><tcp><port>123</port></tcp></protocol></entry></service>
            <service-group><entry name="myservicegroup"><members><member>tcp-123</member></members></entry></service-group>
          </entry></device-group></entry></devices>
          <readonly><devices><entry name="localhost.localdomain"><device-group>
            <entry name="test_dg"><id>11</id></entry>
          </device-group></entry></devices></readonly>
        </config></result></response>
        """
        pan_config = PanConfig(test_xml)

        profilepackage = self.create_profilepackage(pan_config)
        _, _, validator_function = get_policy_validators()['RedundantRuleServices']
        results, count_checks = validator_function(profilepackage)
        self.assertEqual(len(results), 1)
        self.assertEqual(count_checks, 2)
        ruletype, rule_entry, members_to_remove = results[0].data
        self.assertEqual(ruletype, 'SecurityPreRules')
        self.assertEqual(rule_entry.get('name'), 'same_zone_rule')
        self.assertEqual(members_to_remove, [('tcp-123', 'myservicegroup')])


if __name__ == "__main__":
    unittest.main()
