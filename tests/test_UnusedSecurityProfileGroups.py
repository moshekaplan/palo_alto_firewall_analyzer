#!/usr/bin/env python
import collections
import unittest

from palo_alto_firewall_analyzer.core import get_policy_validators
from palo_alto_firewall_analyzer.core import ProfilePackage, ConfigurationSettings
from palo_alto_firewall_analyzer.pan_config import PanConfig


class TestUnusedSecurityProfileGroups(unittest.TestCase):
    @staticmethod
    def create_profilepackage(pan_config):
        device_groups = ["shared"]
        devicegroup_objects = {"shared": collections.defaultdict(list), "test_dg": collections.defaultdict(list)}
        devicegroup_objects['shared']['all_child_device_groups'] = ["shared", "test_dg"]

        profilepackage = ProfilePackage(
            api_key='',
            pan_config=pan_config,
            settings=ConfigurationSettings().get_config(),
            device_group_hierarchy_children={},
            device_group_hierarchy_parent={},
            device_groups_and_firewalls={},
            device_groups=device_groups,
            devicegroup_objects=devicegroup_objects,
            devicegroup_exclusive_objects={},
            rule_limit_enabled=False
        )
        return profilepackage

    def test_unusedaddresses(self):
        test_xml = """\
        <response status="success"><result><config>
          <shared>
            <profile-group>
              <entry name="used_group1"></entry>
              <entry name="used_group2"></entry>
              <entry name="unused_group3"></entry>
            </profile-group>
            <pre-rulebase>
              <security><rules>
                <entry name="shared_rule1"><profile-setting><group><member>used_group1</member></group></profile-setting></entry>
              </rules></security>
            </pre-rulebase>
          </shared>
          <devices><entry><device-group><entry name="test_dg">
            <pre-rulebase>
              <security><rules>
                <entry name="dg_rule2"><profile-setting><group><member>used_group2</member></group></profile-setting></entry>
              </rules></security>
            </pre-rulebase>
          </entry></device-group></entry></devices>
        </config></result></response>
        """
        pan_config = PanConfig(test_xml)
        profilepackage = self.create_profilepackage(pan_config)

        _, _, validator_function = get_policy_validators()['UnusedSecurityProfileGroups']
        results = validator_function(profilepackage)

        self.assertEqual(len(results), 1)
        self.assertEqual(len(results[0].data), 1)
        self.assertEqual(results[0].data[0].get('name'), 'unused_group3')
        self.assertEqual(results[0].device_group, 'shared')


if __name__ == "__main__":
    unittest.main()
