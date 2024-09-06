#!/usr/bin/env python
import unittest
from unittest.mock import patch

from palo_alto_firewall_analyzer.core import get_policy_validators
from palo_alto_firewall_analyzer.core import ProfilePackage, ConfigurationSettings
from palo_alto_firewall_analyzer.pan_config import PanConfig


class TestUnqualifiedFQDN(unittest.TestCase):
    @staticmethod
    def create_profilepackage(addresses, ignored_dns_prefixes):
        device_groups = ["shared"]
        devicegroup_objects = {"shared": {}}
        devicegroup_objects["shared"]['Addresses'] = addresses
        settings = ConfigurationSettings().get_config()
        settings['Ignored DNS Prefixes'] = ",".join(ignored_dns_prefixes)

        profilepackage = ProfilePackage(
            api_key='',
            pan_config=PanConfig('<_/>'),
            settings=settings,
            device_group_hierarchy_children={},
            device_group_hierarchy_parent={},
            device_groups_and_firewalls={},
            device_groups=device_groups,
            devicegroup_objects=devicegroup_objects,
            devicegroup_exclusive_objects={},
            rule_limit_enabled=False
        )
        return profilepackage

    @patch('palo_alto_firewall_analyzer.validators.unqualified_fqdn.cached_fqdn_lookup')
    def test_badhostname(self, mocked_fqdn_lookup):
        test_xml = """\
        <response status="success"><result><config>
          <shared>
            <address>
              <entry name="ignored_missing_fqdn"><fqdn>ignored_missing</fqdn></entry>
              <entry name="missing_fqdn"><fqdn>missing</fqdn></entry>
              <entry name="valid_fqdn"><fqdn>valid.tld</fqdn></entry>
            </address>
          </shared>
        </config></result></response>
        """
        pan_config = PanConfig(test_xml)
        addresses = pan_config.get_devicegroup_object('Addresses', 'shared')
        ignored_dns_prefixes = ["ignored"]
        mocked_fqdn_lookup.side_effect = ['missing.tld']
        profilepackage = self.create_profilepackage(addresses, ignored_dns_prefixes)

        _, _, validator_function = get_policy_validators()['UnqualifiedFQDN']
        results, count_checks = validator_function(profilepackage)
        self.assertEqual(len(results), 1)
        self.assertEqual(count_checks, 3)
        self.assertEqual(results[0].data[0].get('name'), 'missing_fqdn')
        self.assertEqual(results[0].data[1], 'missing.tld')


if __name__ == "__main__":
    unittest.main()
