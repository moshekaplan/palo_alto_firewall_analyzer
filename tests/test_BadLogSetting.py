#!/usr/bin/env python
import unittest

from palo_alto_firewall_analyzer.core import get_policy_validators
from palo_alto_firewall_analyzer.core import ProfilePackage, ConfigurationSettings
from palo_alto_firewall_analyzer.pan_config import PanConfig


class TestBadLogSetting(unittest.TestCase):
    @staticmethod
    def create_profilepackage(mandated_log_profile, rules):
        device_groups = ['test_dg']
        devicegroup_exclusive_objects = {'test_dg': {'SecurityPreRules': rules, 'SecurityPostRules': []}}
        settings = ConfigurationSettings().get_config()
        settings['Mandated Logging Profile'] = mandated_log_profile
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
            rule_limit_enabled=False,
            verbose=False,
            no_api=False
        )
        return profilepackage

    def test_with_mandated_logsetting(self):
        test_xml = """\
        <response status="success"><result><config>
          <devices><entry><device-group><entry name="test_dg">
            <pre-rulebase><security><rules>
              <entry name="disabled_rule"><disabled>yes</disabled></entry>
              <entry name="missing_log-setting"><disabled>no</disabled></entry>
              <entry name="correct_log-setting"><log-setting>correct</log-setting></entry>
              <entry name="wrong_log-setting"><log-setting>wrong</log-setting></entry>
            </rules></security></pre-rulebase>
          </entry></device-group></entry></devices>
        </config></result></response>
        """
        mandated_log_profile = 'correct'
        pan_config = PanConfig(test_xml)
        rules = pan_config.get_devicegroup_policy('SecurityPreRules', 'test_dg')
        profilepackage = self.create_profilepackage(mandated_log_profile, rules)

        _, _, validator_function = get_policy_validators()['BadLogSetting']
        results = validator_function(profilepackage)
        self.assertEqual(len(results), 2)
        self.assertEqual(results[0].data.get('name'), 'missing_log-setting')
        self.assertEqual(results[1].data.get('name'), 'wrong_log-setting')

    def test_without_mandated_logsetting(self):
        test_xml = """\
        <response status="success"><result><config>
          <devices><entry><device-group><entry name="test_dg">
            <pre-rulebase><security><rules>
              <entry name="disabled_rule"><disabled>yes</disabled></entry>
              <entry name="missing_log-setting"><disabled>no</disabled></entry>
              <entry name="correct_log-setting"><log-setting>correct</log-setting></entry>
              <entry name="wrong_log-setting"><log-setting>wrong</log-setting></entry>
            </rules></security></pre-rulebase>
          </entry></device-group></entry></devices>
        </config></result></response>
        """
        mandated_log_profile = None
        pan_config = PanConfig(test_xml)
        rules = pan_config.get_devicegroup_policy('SecurityPreRules', 'test_dg')
        profilepackage = self.create_profilepackage(mandated_log_profile, rules)
        _, _, validator_function = get_policy_validators()['BadLogSetting']
        results = validator_function(profilepackage)
        self.assertEqual(len(results), 0)


if __name__ == "__main__":
    unittest.main()
