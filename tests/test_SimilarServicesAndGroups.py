#!/usr/bin/env python
import unittest

from palo_alto_firewall_analyzer.core import ProfilePackage, ConfigurationSettings
from palo_alto_firewall_analyzer.pan_config import PanConfig
from palo_alto_firewall_analyzer.core import get_policy_validators


class TestSimilarServicesAndGroups(unittest.TestCase):
    @staticmethod
    def create_profilepackage(shared_services, dg_services, shared_service_groups, dg_service_groups):
        device_groups = ["shared", "test_dg"]
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
            rule_limit_enabled=False,
            verbose=False,
            no_api=False
        )
        return profilepackage

    def test_similar_services(self):
        test_xml = """\
        <response status="success"><result><config>
          <shared><service>
              <entry name="shared_service1"/>
              <entry name="SHARED_service1"/>
          </service></shared>
          <devices><entry><device-group><entry name="test_dg">
            <service>
              <entry name="dg_service1"/>
              <entry name="DG_service1"/>
            </service>
          </entry></device-group></entry></devices>
        </config></result></response>
        """
        pan_config = PanConfig(test_xml)
        shared_services = pan_config.get_devicegroup_object('Services', 'shared')
        dg_services = pan_config.get_devicegroup_object('Services', 'test_dg')
        shared_servicegroups = pan_config.get_devicegroup_object('ServiceGroups', 'shared')
        dg_servicegroups = pan_config.get_devicegroup_object('ServiceGroups', 'test_dg')
        profilepackage = self.create_profilepackage(shared_services, dg_services, shared_servicegroups, dg_servicegroups)

        _, _, validator_function = get_policy_validators()['SimilarServicesAndGroups']
        results = validator_function(profilepackage)
        self.assertEqual(len(results), 2)
        self.assertEqual(len(results[0].data), 2)
        self.assertEqual(results[0].data[0][0], 'shared')
        self.assertEqual(results[0].data[0][1], 'Services')
        self.assertEqual(results[0].data[0][2].get('name'), 'shared_service1')
        self.assertEqual(results[0].data[1][0], 'shared')
        self.assertEqual(results[0].data[1][1], 'Services')
        self.assertEqual(results[0].data[1][2].get('name'), 'SHARED_service1')
        self.assertEqual(len(results[1].data), 2)
        self.assertEqual(results[1].data[0][0], 'test_dg')
        self.assertEqual(results[1].data[0][1], 'Services')
        self.assertEqual(results[1].data[0][2].get('name'), 'dg_service1')
        self.assertEqual(results[1].data[1][0], 'test_dg')
        self.assertEqual(results[1].data[1][1], 'Services')
        self.assertEqual(results[1].data[1][2].get('name'), 'DG_service1')

    def test_similar_servicegroups(self):
        test_xml = """\
        <response status="success"><result><config>
          <shared>
            <service-group>
              <entry name="shared_servicegroup1"/>
              <entry name="SHARED_servicegroup1"/>
            </service-group>
          </shared>
          <devices><entry><device-group><entry name="test_dg">
            <service-group>
              <entry name="dg_servicegroup1"/>
              <entry name="DG_servicegroup1"/>
            </service-group>
          </entry></device-group></entry></devices>
        </config></result></response>
        """
        pan_config = PanConfig(test_xml)
        shared_services = pan_config.get_devicegroup_object('Services', 'shared')
        dg_services = pan_config.get_devicegroup_object('Services', 'test_dg')
        shared_servicegroups = pan_config.get_devicegroup_object('ServiceGroups', 'shared')
        dg_servicegroups = pan_config.get_devicegroup_object('ServiceGroups', 'test_dg')
        profilepackage = self.create_profilepackage(shared_services, dg_services, shared_servicegroups, dg_servicegroups)

        _, _, validator_function = get_policy_validators()['SimilarServicesAndGroups']
        results = validator_function(profilepackage)
        self.assertEqual(len(results), 2)
        self.assertEqual(len(results[0].data), 2)
        self.assertEqual(results[0].data[0][0], 'shared')
        self.assertEqual(results[0].data[0][1], 'ServiceGroups')
        self.assertEqual(results[0].data[0][2].get('name'), 'shared_servicegroup1')
        self.assertEqual(results[0].data[1][0], 'shared')
        self.assertEqual(results[0].data[1][1], 'ServiceGroups')
        self.assertEqual(results[0].data[1][2].get('name'), 'SHARED_servicegroup1')
        self.assertEqual(len(results[1].data), 2)
        self.assertEqual(results[1].data[0][0], 'test_dg')
        self.assertEqual(results[1].data[0][1], 'ServiceGroups')
        self.assertEqual(results[1].data[0][2].get('name'), 'dg_servicegroup1')
        self.assertEqual(results[1].data[1][0], 'test_dg')
        self.assertEqual(results[1].data[1][1], 'ServiceGroups')
        self.assertEqual(results[1].data[1][2].get('name'), 'DG_servicegroup1')

    def test_similar_shared_service_and_servicegroups(self):
        test_xml = """\
        <response status="success"><result><config>
          <shared>
            <service>
              <entry name="shared_service_servicegroup1"/>
              <entry name="shared_service_servicegroup2"/>
            </service>
            <service-group>
              <entry name="shared_service_servicegroup1"/>
            </service-group>
          </shared>
          <devices><entry><device-group><entry name="test_dg">
          </entry></device-group></entry></devices>
        </config></result></response>
        """
        pan_config = PanConfig(test_xml)
        shared_services = pan_config.get_devicegroup_object('Services', 'shared')
        dg_services = pan_config.get_devicegroup_object('Services', 'test_dg')
        shared_servicegroups = pan_config.get_devicegroup_object('ServiceGroups', 'shared')
        dg_servicegroups = pan_config.get_devicegroup_object('ServiceGroups', 'test_dg')
        profilepackage = self.create_profilepackage(shared_services, dg_services, shared_servicegroups, dg_servicegroups)

        _, _, validator_function = get_policy_validators()['SimilarServicesAndGroups']
        results = validator_function(profilepackage)
        self.assertEqual(len(results), 1)
        self.assertEqual(len(results[0].data), 2)
        self.assertEqual(results[0].data[0][0], 'shared')
        self.assertEqual(results[0].data[0][1], 'Services')
        self.assertEqual(results[0].data[0][2].get('name'), 'shared_service_servicegroup1')
        self.assertEqual(results[0].data[1][0], 'shared')
        self.assertEqual(results[0].data[1][1], 'ServiceGroups')
        self.assertEqual(results[0].data[1][2].get('name'), 'shared_service_servicegroup1')

    def test_similar_dg_service_and_servicegroups(self):
        test_xml = """\
        <response status="success"><result><config>
          <shared>
          </shared>
          <devices><entry><device-group><entry name="test_dg">
            <service>
              <entry name="dg_SERVICE_servicegroup1"/>
            </service>
            <service-group>
              <entry name="dg_service_SERVICEGROUP1"/>
            </service-group>
          </entry></device-group></entry></devices>
        </config></result></response>
        """
        pan_config = PanConfig(test_xml)
        shared_services = pan_config.get_devicegroup_object('Services', 'shared')
        dg_services = pan_config.get_devicegroup_object('Services', 'test_dg')
        shared_servicegroups = pan_config.get_devicegroup_object('ServiceGroups', 'shared')
        dg_servicegroups = pan_config.get_devicegroup_object('ServiceGroups', 'test_dg')
        profilepackage = self.create_profilepackage(shared_services, dg_services, shared_servicegroups, dg_servicegroups)

        _, _, validator_function = get_policy_validators()['SimilarServicesAndGroups']
        results = validator_function(profilepackage)
        self.assertEqual(len(results), 1)
        self.assertEqual(len(results[0].data), 2)
        self.assertEqual(results[0].data[0][0], 'test_dg')
        self.assertEqual(results[0].data[0][1], 'Services')
        self.assertEqual(results[0].data[0][2].get('name'), 'dg_SERVICE_servicegroup1')
        self.assertEqual(results[0].data[1][0], 'test_dg')
        self.assertEqual(results[0].data[1][1], 'ServiceGroups')
        self.assertEqual(results[0].data[1][2].get('name'), 'dg_service_SERVICEGROUP1')

    def test_similar_shared_service_and_dg_servicegroups(self):
        # SimilarServicesAndGroups previously detected
        # duplicates across device groups. This test is
        # being kept to ensure behavior is as expected.
        test_xml = """\
        <response status="success"><result><config>
          <shared>
            <service-group>
              <entry name="SHARED_service_and_dg_servicegroup"/>
            </service-group>
          </shared>
          <devices><entry><device-group><entry name="test_dg">
            <service>
              <entry name="shared_service_and_DG_servicegroup"/>
            </service>
          </entry></device-group></entry></devices>
        </config></result></response>
        """
        pan_config = PanConfig(test_xml)
        shared_services = pan_config.get_devicegroup_object('Services', 'shared')
        dg_services = pan_config.get_devicegroup_object('Services', 'test_dg')
        shared_servicegroups = pan_config.get_devicegroup_object('ServiceGroups', 'shared')
        dg_servicegroups = pan_config.get_devicegroup_object('ServiceGroups', 'test_dg')
        profilepackage = self.create_profilepackage(shared_services, dg_services, shared_servicegroups, dg_servicegroups)

        _, _, validator_function = get_policy_validators()['SimilarServicesAndGroups']
        results = validator_function(profilepackage)
        self.assertEqual(len(results), 0)


if __name__ == "__main__":
    unittest.main()
