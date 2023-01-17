#!/usr/bin/env python
import unittest

from palo_alto_firewall_analyzer.core import get_policy_validators
from palo_alto_firewall_analyzer.core import ProfilePackage, ConfigurationSettings
from palo_alto_firewall_analyzer.pan_config import PanConfig


class TestMisleadingAddresses(unittest.TestCase):
    @staticmethod
    def create_profilepackage(addresses):
        device_groups = ["shared"]
        devicegroup_objects = {"shared": {}}
        devicegroup_objects["shared"]['Addresses'] = addresses
        devicegroup_exclusive_objects = {'shared': {'SecurityPreRules': [], 'SecurityPostRules': []}}

        profilepackage = ProfilePackage(
            api_key='',
            pan_config=PanConfig('<_/>'),
            settings=ConfigurationSettings().get_config(),
            device_group_hierarchy_children={},
            device_group_hierarchy_parent={},
            device_groups_and_firewalls={},
            device_groups=device_groups,
            devicegroup_objects=devicegroup_objects,
            devicegroup_exclusive_objects=devicegroup_exclusive_objects,
            rule_limit_enabled=False
        )
        return profilepackage

    def test_misleading_addresses(self):
        test_xml = """\
        <response status="success"><result><config><shared><address>
            <entry name="valid_ip_127.0.0.1"><ip-netmask>127.0.0.1</ip-netmask></entry>
            <entry name="invalid_ip_127.0.0.2"><ip-netmask>127.0.0.1</ip-netmask></entry>
            <entry name="valid_range_127.0.0.1"><ip-range>127.0.0.1-127.0.0.255</ip-range></entry>
            <entry name="invalid_range_128.0.0.1"><ip-range>127.0.0.1-127.0.0.255</ip-range></entry>
            <entry name="valid_fqdn_valid.tld"><fqdn>valid.tld</fqdn></entry>
            <entry name="invalid_fqdn_invalid.tld"><fqdn>missing.invalid.tld</fqdn></entry>
        </address></shared></config></result></response>
        """
        pan_config = PanConfig(test_xml)
        addresses = pan_config.get_devicegroup_object('Addresses', 'shared')
        profilepackage = self.create_profilepackage(addresses)

        _, _, validator_function = get_policy_validators()['MisleadingAddresses']
        results = validator_function(profilepackage)
        self.assertEqual(len(results), 3)
        self.assertEqual(results[0].data.get('name'), 'invalid_ip_127.0.0.2')
        self.assertEqual(results[1].data.get('name'), 'invalid_range_128.0.0.1')
        self.assertEqual(results[2].data.get('name'), 'invalid_fqdn_invalid.tld')


if __name__ == "__main__":
    unittest.main()
