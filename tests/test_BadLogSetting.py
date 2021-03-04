#!/usr/bin/env python
import unittest

from palo_alto_firewall_analyzer.core import ProfilePackage
from palo_alto_firewall_analyzer.pan_config import PanConfig
from palo_alto_firewall_analyzer.validators.bad_log_setting import find_bad_log_setting


class TestBadLogSetting(unittest.TestCase):
    @staticmethod
    def create_profilepackage(mandated_log_profile, rules):
        device_groups = ['test_dg']
        devicegroup_exclusive_objects = {'test_dg': {'SecurityPreRules': rules, 'SecurityPostRules': []}}

        profilepackage = ProfilePackage(
            panorama='',
            version='',
            api_key='',
            pan_config=PanConfig('<_/>'),
            mandated_log_profile=mandated_log_profile,
            allowed_group_profiles=[],
            default_group_profile='',
            ignored_dns_prefixes=[],
            device_group_hierarchy_children={},
            device_group_hierarchy_parent={},
            device_groups_and_firewalls={},
            device_groups=device_groups,
            devicegroup_objects={},
            devicegroup_exclusive_objects=devicegroup_exclusive_objects,
            rule_limit_enabled=False,
            verbose=False
        )
        return profilepackage

    def test_with_mandated_profile(self):
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
        rules = pan_config.get_devicegroup_policy('SecurityPreRules', 'device-group', 'test_dg')
        profilepackage = self.create_profilepackage(mandated_log_profile, rules)

        results = find_bad_log_setting(profilepackage)
        self.assertEqual(len(results), 2)
        self.assertEqual(results[0].data.get('name'), 'missing_log-setting')
        self.assertEqual(results[1].data.get('name'), 'wrong_log-setting')

    def test_without_mandated_profile(self):
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
        rules = pan_config.get_devicegroup_policy('SecurityPreRules', 'device-group', 'test_dg')
        profilepackage = self.create_profilepackage(mandated_log_profile, rules)
        results = (find_bad_log_setting(profilepackage))
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].data.get('name'), 'missing_log-setting')


if __name__ == "__main__":
    unittest.main()
