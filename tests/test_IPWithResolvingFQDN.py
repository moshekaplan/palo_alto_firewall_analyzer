#!/usr/bin/env python
import unittest
from unittest.mock import patch

from palo_alto_firewall_analyzer.core import get_policy_validators
from palo_alto_firewall_analyzer.core import ProfilePackage, ConfigurationSettings
from palo_alto_firewall_analyzer.pan_config import PanConfig


class TestIPWithResolvingFQDN(unittest.TestCase):
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
            devicegroup_objects={},
            devicegroup_exclusive_objects={},
            rule_limit_enabled=False,
            no_api=False
        )
        return profilepackage

    @patch('palo_alto_firewall_analyzer.validators.ip_with_resolving_fqdn.cached_dns_ex_lookup')
    def test_IPWithResolvingFQDN(self, mocked_dns_lookup):
        test_xml = """\
        <response status="success"><result><config>
          <shared>
            <pre-rulebase><security><rules>
              <entry name="test_rule">
                <source><member>invalid_fqdn</member></source>
                <destination><member>ignored_fqdn</member></destination>
              </entry>
            </rules></security></pre-rulebase>
            <address>
              <entry name="redundant_ip"><ip-netmask>127.0.0.1/32</ip-netmask></entry>
              <entry name="valid_fqdn"><fqdn>valid.tld</fqdn></entry>
              <entry name="invalid_fqdn"><fqdn>invalid.bad.tld</fqdn></entry>
            </address>
          </shared>
        </config></result></response>
        """
        pan_config = PanConfig(test_xml)
        mocked_dns_lookup.side_effect = [('valid.tld', [], ["127.0.0.1"]), (None, [], [])]
        profilepackage = self.create_profilepackage(pan_config)

        _, _, validator_function = get_policy_validators()['IPWithResolvingFQDN']
        results = validator_function(profilepackage)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].data[0].get('name'), 'redundant_ip')
        self.assertEqual(results[0].data[1], 'valid.tld')


if __name__ == "__main__":
    unittest.main()
