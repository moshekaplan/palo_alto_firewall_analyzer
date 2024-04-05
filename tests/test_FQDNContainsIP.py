#!/usr/bin/env python
import unittest
from unittest.mock import patch

from palo_alto_firewall_analyzer.core import get_policy_validators
from palo_alto_firewall_analyzer.core import ProfilePackage, ConfigurationSettings
from palo_alto_firewall_analyzer.pan_config import PanConfig


class TestFQDNContainsIP(unittest.TestCase):
    @staticmethod
    def create_profilepackage(pan_config):
        device_groups = ["shared"]
        settings = ConfigurationSettings().get_config()

        profilepackage = ProfilePackage(
            api_key='',
            pan_config=pan_config,
            settings=settings,
            device_group_hierarchy_children={},
            device_group_hierarchy_parent={},
            device_groups_and_firewalls={},
            device_groups=device_groups,
            devicegroup_objects=[],
            devicegroup_exclusive_objects=[],
            rule_limit_enabled=False
        )
        return profilepackage

    def test_badfqdn(self):
        test_xml = """\
        <response status="success"><result><config>
          <shared>
            <address>
              <entry name="ignored_ip_netmask"><ip-netmask>127.0.0.1</ip-netmask></entry>
              <entry name="fqdn_with_ip"><fqdn>127.0.0.1</fqdn></entry>
              <entry name="good_fqdn"><fqdn>good.tld</fqdn></entry>
            </address>
          </shared>
        </config></result></response>
        """
        pan_config = PanConfig(test_xml)
        profilepackage = self.create_profilepackage(pan_config)

        _, _, validator_function = get_policy_validators()['FQDNContainsIP']
        results, count_checks = validator_function(profilepackage)
        self.assertEqual(len(results), 1)
        self.assertEqual(count_checks, 2)
        self.assertEqual(results[0].data.get('name'), 'fqdn_with_ip')


if __name__ == "__main__":
    unittest.main()
