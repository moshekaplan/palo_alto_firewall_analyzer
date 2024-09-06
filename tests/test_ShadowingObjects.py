#!/usr/bin/env python
import unittest

from palo_alto_firewall_analyzer.core import get_policy_validators
from palo_alto_firewall_analyzer.core import ProfilePackage, ConfigurationSettings
from palo_alto_firewall_analyzer.pan_config import PanConfig


class TestShadowingObjects(unittest.TestCase):
    @staticmethod
    def create_profilepackage(shared_services, dg_services, shared_service_groups, dg_service_groups):
        device_groups = ["test_dg"]
        device_group_hierarchy_parent = {"test_dg": "shared"}
        devicegroup_objects = {"shared": {}, "test_dg": {}}
        devicegroup_objects["shared"]['Services'] = shared_services
        devicegroup_objects["test_dg"]['Services'] = dg_services
        devicegroup_objects["shared"]['ServiceGroups'] = shared_service_groups
        devicegroup_objects["test_dg"]['ServiceGroups'] = dg_service_groups

        profilepackage = ProfilePackage(
            api_key='',
            pan_config=PanConfig('<_/>'),
            settings=ConfigurationSettings().get_config(),
            device_group_hierarchy_children={},
            device_group_hierarchy_parent=device_group_hierarchy_parent,
            device_groups_and_firewalls={},
            device_groups=device_groups,
            devicegroup_objects=devicegroup_objects,
            devicegroup_exclusive_objects={},
            rule_limit_enabled=False
        )
        return profilepackage

    def test_shadowing_services(self):
        test_xml = """\
        <response status="success"><result><config>
          <shared>
            <service>
              <entry name="tcp-nondup"><protocol><tcp><port>1</port><override><no/></override></tcp></protocol></entry>
              <entry name="tcp-dup"><protocol><tcp><port>2</port><override><no/></override></tcp></protocol></entry>
            </service>
          </shared>
          <devices><entry><device-group><entry name="test_dg">
            <service>
              <entry name="tcp-dup"><protocol><tcp><port>2</port><override><no/></override></tcp></protocol></entry>
            </service>
          </entry></device-group></entry></devices>
        </config></result></response>
        """
        pan_config = PanConfig(test_xml)
        shared_services = pan_config.get_devicegroup_object('Services', 'shared')
        dg_services = pan_config.get_devicegroup_object('Services', 'test_dg')
        profilepackage = self.create_profilepackage(shared_services, dg_services, [], [])

        _, _, validator_function = get_policy_validators()['ShadowingServices']
        results, count_checks = validator_function(profilepackage)

        self.assertEqual(len(results), 1)
        self.assertEqual(count_checks, 1)
        self.assertEqual(len(results[0].data), 2)
        self.assertEqual(results[0].data[0][0], 'shared')
        self.assertEqual(results[0].data[0][1].get('name'), 'tcp-dup')
        self.assertEqual(results[0].data[1][0], 'test_dg')
        self.assertEqual(results[0].data[1][1].get('name'), 'tcp-dup')

    def test_shadowing_servicegroups(self):
        test_xml = """\
        <response status="success"><result><config>
          <shared>
            <service-group>
              <entry name="uniquegroup1"><members><member>mem1</member><member>mem2</member></members></entry>
              <entry name="dupgroup1"><members><member>mem1</member><member>mem2</member></members></entry>
            </service-group>
          </shared>
          <devices><entry><device-group><entry name="test_dg">
            <service-group>
              <entry name="dupgroup1"><members><member>mem1</member><member>mem2</member></members></entry>
              <entry name="uniquegroup2"><members><member>mem1</member><member>mem2</member></members></entry>
            </service-group>
          </entry></device-group></entry></devices>
        </config></result></response>
        """
        pan_config = PanConfig(test_xml)
        shared_service_groups = pan_config.get_devicegroup_object('ServiceGroups', 'shared')
        dg_service_groups = pan_config.get_devicegroup_object('ServiceGroups', 'test_dg')

        profilepackage = self.create_profilepackage([], [], shared_service_groups, dg_service_groups)

        _, _, validator_function = get_policy_validators()['ShadowingServiceGroups']
        results, count_checks = validator_function(profilepackage)
        self.assertEqual(len(results), 1)
        self.assertEqual(count_checks, 1)
        self.assertEqual(len(results[0].data), 2)
        self.assertEqual(results[0].data[0][0], 'shared')
        self.assertEqual(results[0].data[0][1].get('name'), 'dupgroup1')
        self.assertEqual(results[0].data[1][0], 'test_dg')
        self.assertEqual(results[0].data[1][1].get('name'), 'dupgroup1')

if __name__ == "__main__":
    unittest.main()
