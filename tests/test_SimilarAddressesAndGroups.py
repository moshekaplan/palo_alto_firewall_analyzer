#!/usr/bin/env python
import unittest

from palo_alto_firewall_analyzer.core import ProfilePackage, ConfigurationSettings
from palo_alto_firewall_analyzer.pan_config import PanConfig
from palo_alto_firewall_analyzer.core import get_policy_validators


class TestSimilarAddressesAndGroups(unittest.TestCase):
    @staticmethod
    def create_profilepackage(shared_addresses, dg_addresses, shared_address_groups, dg_address_groups):
        device_groups = ["shared", "test_dg"]
        device_group_hierarchy_parent = {"test_dg": "shared"}
        devicegroup_objects = {"shared": {}, "test_dg": {}}
        devicegroup_objects["shared"]['Addresses'] = shared_addresses
        devicegroup_objects["test_dg"]['Addresses'] = dg_addresses
        devicegroup_objects["shared"]['AddressGroups'] = shared_address_groups
        devicegroup_objects["test_dg"]['AddressGroups'] = dg_address_groups

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
            no_api=False
        )
        return profilepackage

    def test_similar_addresses(self):
        test_xml = """\
        <response status="success"><result><config>
          <shared>
            <address>
              <entry name="shared_address1"/>
              <entry name="SHARED_address1"/>
            </address>
          </shared>
          <devices><entry><device-group><entry name="test_dg">
            <address>
              <entry name="dg_address1"/>
              <entry name="DG_address1"/>
            </address>
          </entry></device-group></entry></devices>
        </config></result></response>
        """
        pan_config = PanConfig(test_xml)
        shared_addresses = pan_config.get_devicegroup_object('Addresses', 'shared')
        dg_addesses = pan_config.get_devicegroup_object('Addresses', 'test_dg')
        shared_addressgroups = pan_config.get_devicegroup_object('AddressGroups', 'shared')
        dg_addessgroups = pan_config.get_devicegroup_object('AddressGroups', 'test_dg')
        profilepackage = self.create_profilepackage(shared_addresses, dg_addesses, shared_addressgroups, dg_addessgroups)

        _, _, validator_function = get_policy_validators()['SimilarAddressesAndGroups']
        results = validator_function(profilepackage)
        self.assertEqual(len(results), 2)
        self.assertEqual(len(results[0].data), 2)
        self.assertEqual(results[0].data[0][0], 'shared')
        self.assertEqual(results[0].data[0][1], 'Addresses')
        self.assertEqual(results[0].data[0][2].get('name'), 'shared_address1')
        self.assertEqual(results[0].data[1][0], 'shared')
        self.assertEqual(results[0].data[1][1], 'Addresses')
        self.assertEqual(results[0].data[1][2].get('name'), 'SHARED_address1')
        self.assertEqual(len(results[1].data), 2)
        self.assertEqual(results[1].data[0][0], 'test_dg')
        self.assertEqual(results[1].data[0][1], 'Addresses')
        self.assertEqual(results[1].data[0][2].get('name'), 'dg_address1')
        self.assertEqual(results[1].data[1][0], 'test_dg')
        self.assertEqual(results[1].data[1][1], 'Addresses')
        self.assertEqual(results[1].data[1][2].get('name'), 'DG_address1')

    def test_similar_addressgroups(self):
        test_xml = """\
        <response status="success"><result><config>
          <shared>
            <address-group>
              <entry name="shared_addressgroup1"/>
              <entry name="SHARED_addressgroup1"/>
            </address-group>
          </shared>
          <devices><entry><device-group><entry name="test_dg">
            <address-group>
              <entry name="dg_addressgroup1"/>
              <entry name="DG_addressgroup1"/>
            </address-group>
          </entry></device-group></entry></devices>
        </config></result></response>
        """
        pan_config = PanConfig(test_xml)
        shared_addresses = pan_config.get_devicegroup_object('Addresses', 'shared')
        dg_addesses = pan_config.get_devicegroup_object('Addresses', 'test_dg')
        shared_addressgroups = pan_config.get_devicegroup_object('AddressGroups', 'shared')
        dg_addessgroups = pan_config.get_devicegroup_object('AddressGroups', 'test_dg')
        profilepackage = self.create_profilepackage(shared_addresses, dg_addesses, shared_addressgroups, dg_addessgroups)

        _, _, validator_function = get_policy_validators()['SimilarAddressesAndGroups']
        results = validator_function(profilepackage)
        self.assertEqual(len(results), 2)
        self.assertEqual(len(results[0].data), 2)
        self.assertEqual(results[0].data[0][0], 'shared')
        self.assertEqual(results[0].data[0][1], 'AddressGroups')
        self.assertEqual(results[0].data[0][2].get('name'), 'shared_addressgroup1')
        self.assertEqual(results[0].data[1][0], 'shared')
        self.assertEqual(results[0].data[1][1], 'AddressGroups')
        self.assertEqual(results[0].data[1][2].get('name'), 'SHARED_addressgroup1')
        self.assertEqual(len(results[1].data), 2)
        self.assertEqual(results[1].data[0][0], 'test_dg')
        self.assertEqual(results[1].data[0][1], 'AddressGroups')
        self.assertEqual(results[1].data[0][2].get('name'), 'dg_addressgroup1')
        self.assertEqual(results[1].data[1][0], 'test_dg')
        self.assertEqual(results[1].data[1][1], 'AddressGroups')
        self.assertEqual(results[1].data[1][2].get('name'), 'DG_addressgroup1')

    def test_similar_shared_address_and_addressgroups(self):
        test_xml = """\
        <response status="success"><result><config>
          <shared>
            <address>
              <entry name="shared_address_addressgroup1"/>
              <entry name="shared_address_addressgroup2"/>
            </address>
            <address-group>
              <entry name="shared_address_addressgroup1"/>
            </address-group>
          </shared>
          <devices><entry><device-group><entry name="test_dg">
          </entry></device-group></entry></devices>
        </config></result></response>
        """
        pan_config = PanConfig(test_xml)
        shared_addresses = pan_config.get_devicegroup_object('Addresses', 'shared')
        dg_addesses = pan_config.get_devicegroup_object('Addresses', 'test_dg')
        shared_addressgroups = pan_config.get_devicegroup_object('AddressGroups', 'shared')
        dg_addessgroups = pan_config.get_devicegroup_object('AddressGroups', 'test_dg')
        profilepackage = self.create_profilepackage(shared_addresses, dg_addesses, shared_addressgroups, dg_addessgroups)

        _, _, validator_function = get_policy_validators()['SimilarAddressesAndGroups']
        results = validator_function(profilepackage)
        self.assertEqual(len(results), 1)
        self.assertEqual(len(results[0].data), 2)
        self.assertEqual(results[0].data[0][0], 'shared')
        self.assertEqual(results[0].data[0][1], 'Addresses')
        self.assertEqual(results[0].data[0][2].get('name'), 'shared_address_addressgroup1')
        self.assertEqual(results[0].data[1][0], 'shared')
        self.assertEqual(results[0].data[1][1], 'AddressGroups')
        self.assertEqual(results[0].data[1][2].get('name'), 'shared_address_addressgroup1')

    def test_similar_dg_address_and_addressgroups(self):
        test_xml = """\
        <response status="success"><result><config>
          <shared>
          </shared>
          <devices><entry><device-group><entry name="test_dg">
            <address>
              <entry name="dg_ADDRESS_addressgroup1"/>
            </address>
            <address-group>
              <entry name="dg_address_ADDRESSGROUP1"/>
            </address-group>
          </entry></device-group></entry></devices>
        </config></result></response>
        """
        pan_config = PanConfig(test_xml)
        shared_addresses = pan_config.get_devicegroup_object('Addresses', 'shared')
        dg_addesses = pan_config.get_devicegroup_object('Addresses', 'test_dg')
        shared_addressgroups = pan_config.get_devicegroup_object('AddressGroups', 'shared')
        dg_addessgroups = pan_config.get_devicegroup_object('AddressGroups', 'test_dg')
        profilepackage = self.create_profilepackage(shared_addresses, dg_addesses, shared_addressgroups, dg_addessgroups)

        _, _, validator_function = get_policy_validators()['SimilarAddressesAndGroups']
        results = validator_function(profilepackage)
        self.assertEqual(len(results), 1)
        self.assertEqual(len(results[0].data), 2)
        self.assertEqual(results[0].data[0][0], 'test_dg')
        self.assertEqual(results[0].data[0][1], 'Addresses')
        self.assertEqual(results[0].data[0][2].get('name'), 'dg_ADDRESS_addressgroup1')
        self.assertEqual(results[0].data[1][0], 'test_dg')
        self.assertEqual(results[0].data[1][1], 'AddressGroups')
        self.assertEqual(results[0].data[1][2].get('name'), 'dg_address_ADDRESSGROUP1')

    def test_similar_shared_address_and_dg_addressgroups(self):
        # SimilarAddressesAndGroups previously detected
        # duplicates across device groups. This test is
        # being kept to ensure behavior is as expected.
        test_xml = """\
        <response status="success"><result><config>
          <shared>
            <address-group>
              <entry name="SHARED_address_and_dg_addressgroup"/>
            </address-group>
          </shared>
          <devices><entry><device-group><entry name="test_dg">
            <address>
              <entry name="shared_address_and_DG_addressgroup"/>
            </address>
          </entry></device-group></entry></devices>
        </config></result></response>
        """
        pan_config = PanConfig(test_xml)
        shared_addresses = pan_config.get_devicegroup_object('Addresses', 'shared')
        dg_addesses = pan_config.get_devicegroup_object('Addresses', 'test_dg')
        shared_addressgroups = pan_config.get_devicegroup_object('AddressGroups', 'shared')
        dg_addessgroups = pan_config.get_devicegroup_object('AddressGroups', 'test_dg')
        profilepackage = self.create_profilepackage(shared_addresses, dg_addesses, shared_addressgroups, dg_addessgroups)

        _, _, validator_function = get_policy_validators()['SimilarAddressesAndGroups']
        results = validator_function(profilepackage)
        self.assertEqual(len(results), 0)


if __name__ == "__main__":
    unittest.main()
