#!/usr/bin/env python
import unittest

from palo_alto_firewall_analyzer.core import get_policy_validators
from palo_alto_firewall_analyzer.core import ProfilePackage, ConfigurationSettings
from palo_alto_firewall_analyzer.pan_config import PanConfig


class TestBadGroupProfile(unittest.TestCase):
    @staticmethod
    def create_profilepackage(allowed_group_profile, pan_config):
        device_groups = ['test_dg']
        rules = pan_config.get_devicegroup_policy('SecurityPreRules', 'test_dg')
        devicegroup_exclusive_objects = {'test_dg': {'SecurityPreRules': rules, 'SecurityPostRules': []}}

        settings = ConfigurationSettings().get_config()
        settings['Allowed Group Profiles'] = allowed_group_profile

        profilepackage = ProfilePackage(
            api_key='',
            pan_config=PanConfig('<_/>'),
            settings=settings,
            device_group_hierarchy_children={},
            device_group_hierarchy_parent={},
            device_groups_and_firewalls={},
            device_groups=device_groups,
            devicegroup_objects={},
            devicegroup_exclusive_objects=devicegroup_exclusive_objects,
            rule_limit_enabled=False
        )
        return profilepackage

    def test_with_mandated_profile(self):
        test_xml = """\
        <response status="success"><result><config>
          <devices><entry><device-group><entry name="test_dg">
            <pre-rulebase><security><rules>
              <entry name="disabled_rule"><disabled>yes</disabled></entry>
              <entry name="missing_gp"></entry>
              <entry name="correct_gp"><profile-setting><group><member>correct</member></group></profile-setting></entry>
              <entry name="wrong_gp"><profile-setting><group><member>wrong</member></group></profile-setting></entry>
            </rules></security></pre-rulebase>
          </entry></device-group></entry></devices>
        </config></result></response>
        """
        allowed_group_profile = 'correct'
        pan_config = PanConfig(test_xml)
        profilepackage = self.create_profilepackage(allowed_group_profile, pan_config)

        _, _, validator_function = get_policy_validators()['BadGroupProfile']
        results, count_checks = validator_function(profilepackage)        
        self.assertEqual(len(results), 2)
        self.assertEqual(count_checks,4)
        self.assertEqual(results[0].data.get('name'), 'missing_gp')
        self.assertEqual(results[1].data.get('name'), 'wrong_gp')


if __name__ == "__main__":
    unittest.main()
