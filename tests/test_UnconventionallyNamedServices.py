#!/usr/bin/env python
import unittest

from palo_alto_firewall_analyzer.core import get_policy_validators
from palo_alto_firewall_analyzer.core import ProfilePackage, ConfigurationSettings
from palo_alto_firewall_analyzer.pan_config import PanConfig


class TestUnconventionallyNamedServices(unittest.TestCase):
    @staticmethod
    def create_profilepackage(pan_config, service_name_format):
        device_groups = ["shared"]
        settings = ConfigurationSettings().get_config()
        settings['service name format'] = service_name_format
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

    def test_misleading_services(self):
        test_xml = """\
        <response status="success"><result><config><shared><service>
            <entry name="prefix-tcp-123"><protocol><tcp><port>123</port></tcp></protocol></entry>
            <entry name="prefix-tcp-1234"><protocol><tcp><port>123</port></tcp></protocol></entry>
            <entry name="prefix-udp-123"><protocol><udp><port>123</port></udp></protocol></entry>
            <entry name="prefix-udp-1234"><protocol><udp><port>123</port></udp></protocol></entry>
            <entry name="missing-tcp-123"><protocol><udp><port>1234</port></udp></protocol></entry>
        </service></shared></config></result></response>
        """
        pan_config = PanConfig(test_xml)
        service_name_format = 'prefix-{transport}-{port}'
        profilepackage = self.create_profilepackage(pan_config, service_name_format)

        _, _, validator_function = get_policy_validators()['UnconventionallyNamedServices']
        results = validator_function(profilepackage)
        self.assertEqual(len(results), 3)
        self.assertEqual(results[0].data[0].get('name'), 'prefix-tcp-1234')
        self.assertEqual(results[0].data[1], 'prefix-tcp-123')
        self.assertEqual(results[1].data[0].get('name'), 'prefix-udp-1234')
        self.assertEqual(results[1].data[1], 'prefix-udp-123')
        self.assertEqual(results[2].data[0].get('name'), 'missing-tcp-123')
        self.assertEqual(results[2].data[1], 'prefix-udp-1234')


if __name__ == "__main__":
    unittest.main()
