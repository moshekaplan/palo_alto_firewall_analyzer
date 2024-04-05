#!/usr/bin/env python
import unittest

from palo_alto_firewall_analyzer.core import get_policy_validators
from palo_alto_firewall_analyzer.core import ProfilePackage, ConfigurationSettings
from palo_alto_firewall_analyzer.pan_config import PanConfig


class TestRulesMissingSecurityProfile(unittest.TestCase):
    @staticmethod
    def create_profilepackage(pan_config, default_security_profile_group):
        device_groups = ['test_dg']
        settings = ConfigurationSettings().get_config()
        settings['Default Security Profile Group'] = default_security_profile_group
        profilepackage = ProfilePackage(
            api_key='',
            pan_config=pan_config,
            settings=settings,
            device_group_hierarchy_children={},
            device_group_hierarchy_parent={},
            device_groups_and_firewalls={},
            device_groups=device_groups,
            devicegroup_objects={},
            devicegroup_exclusive_objects={},
            rule_limit_enabled=False
        )
        return profilepackage

    def test_with_profilegroup(self):
        test_xml = """\
        <response status="success"><result><config>
          <devices><entry><device-group><entry name="test_dg">
            <pre-rulebase><security><rules>
              <entry name="disabled_rule"><disabled>yes</disabled></entry>
              <entry name="deny_rule"><action>deny</action></entry>
              <entry name="nothing_assigned"><action>allow</action></entry>
              <entry name="group_of_none_assigned"><action>allow</action><profile-setting><group></group></profile-setting></entry>
              <entry name="security_profile_group_present"><action>allow</action><profile-setting><group><member>correct</member></group></profile-setting></entry>
            </rules></security></pre-rulebase>
          </entry></device-group></entry></devices>
        </config></result></response>
        """
        mandated_log_profile = 'default'
        pan_config = PanConfig(test_xml)
        profilepackage = self.create_profilepackage(pan_config, mandated_log_profile)

        _, _, validator_function = get_policy_validators()['RulesMissingSecurityProfile']
        results, count_checks = validator_function(profilepackage)
        self.assertEqual(len(results), 2)
        self.assertEqual(count_checks, 5)
        self.assertEqual(results[0].data.get('name'), 'nothing_assigned')
        self.assertEqual(results[1].data.get('name'), 'group_of_none_assigned')


if __name__ == "__main__":
    unittest.main()
