#!/usr/bin/env python
import unittest

from palo_alto_firewall_analyzer.core import get_policy_validators
from palo_alto_firewall_analyzer.core import ProfilePackage, ConfigurationSettings
from palo_alto_firewall_analyzer.pan_config import PanConfig


class TestMisleadingServices(unittest.TestCase):
    @staticmethod
    def create_profilepackage(services):
        device_groups = ["shared"]
        devicegroup_objects = {"shared": {}}
        devicegroup_objects["shared"]['Services'] = services

        profilepackage = ProfilePackage(
            api_key='',
            pan_config=PanConfig('<_/>'),
            settings=ConfigurationSettings().get_config(),
            device_group_hierarchy_children={},
            device_group_hierarchy_parent={},
            device_groups_and_firewalls={},
            device_groups=device_groups,
            devicegroup_objects=devicegroup_objects,
            devicegroup_exclusive_objects=[],
            rule_limit_enabled=False,
            verbose=False,
            no_api=False
        )
        return profilepackage

    def test_misleading_services(self):
        test_xml = """\
        <response status="success"><result><config><shared><service>
            <entry name="valid-tcp-123"><protocol><tcp><port>123</port></tcp></protocol></entry>
            <entry name="valid-tcp-1234"><protocol><tcp><port>123</port></tcp></protocol></entry>
            <entry name="valid-udp-123"><protocol><udp><port>123</port></udp></protocol></entry>
            <entry name="valid-udp-1234"><protocol><udp><port>123</port></udp></protocol></entry>
            <entry name="invalid-protocol-tcp-123"><protocol><udp><port>123</port></udp></protocol></entry>
            <entry name="invalid-protocol-udp-1234"><protocol><tcp><port>123</port></tcp></protocol></entry>
            <entry name="invalid-port-1233"><protocol><udp><port>1234</port></udp></protocol></entry>
            <entry name="invalid-port-and-protocol-tcp-123"><protocol><udp><port>1234</port></udp></protocol></entry>
        </service></shared></config></result></response>
        """
        pan_config = PanConfig(test_xml)
        services = pan_config.get_devicegroup_object('Services', 'shared')
        profilepackage = self.create_profilepackage(services)

        _, _, validator_function = get_policy_validators()['MisleadingServices']
        results = validator_function(profilepackage)
        self.assertEqual(len(results), 4)
        self.assertEqual(results[0].data.get('name'), 'invalid-protocol-tcp-123')
        self.assertEqual(results[1].data.get('name'), 'invalid-protocol-udp-1234')
        self.assertEqual(results[2].data.get('name'), 'invalid-port-1233')
        self.assertEqual(results[3].data.get('name'), 'invalid-port-and-protocol-tcp-123')


if __name__ == "__main__":
    unittest.main()
