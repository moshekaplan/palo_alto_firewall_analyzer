#!/usr/bin/env python
import unittest

from palo_alto_firewall_analyzer.core import get_policy_validators
from palo_alto_firewall_analyzer.core import ProfilePackage, ConfigurationSettings
from palo_alto_firewall_analyzer.pan_config import PanConfig


class TestShadowingAddressesAndGroups(unittest.TestCase):
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
            rule_limit_enabled=False
        )
        return profilepackage

    def test_shadowing_addresses_and_groups_unique(self):
        test_xml = """\
        <response status="success"><result><config>
          <shared>
            <address>
              <entry name="unique_shared_address"/>
            </address>
            <address-group>
              <entry name="unique_shared_address_group"/>
            </address-group>
          </shared>
          <devices><entry><device-group><entry name="test_dg">
            <address>
              <entry name="unique_dg_address"/>
            </address>
            <address-group>
              <entry name="unique_dg_address_group"/>
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

        _, _, validator_function = get_policy_validators()['ShadowingAddressesAndGroups']
        results = validator_function(profilepackage)
        self.assertEqual(len(results), 0)

    def test_dup_in_shared(self):
        test_xml = """\
        <response status="success"><result><config>
          <shared>
            <address>
              <entry name="unique_shared_address"/>
              <entry name="dup_within_shared"/>
            </address>
            <address-group>
              <entry name="unique_shared_address_group"/>
              <entry name="dup_within_shared"/>
            </address-group>
          </shared>
          <devices><entry><device-group><entry name="test_dg">
            <address>
            </address>
            <address-group>
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

        _, _, validator_function = get_policy_validators()['ShadowingAddressesAndGroups']
        results = validator_function(profilepackage)
        self.assertEqual(len(results), 1)
        self.assertEqual(len(results[0].data), 2)
        self.assertEqual(results[0].data[0][0], 'shared')
        self.assertEqual(results[0].data[0][1], 'AddressGroups')
        self.assertEqual(results[0].data[0][2].get('name'), 'dup_within_shared')
        self.assertEqual(results[0].data[1][0], 'shared')
        self.assertEqual(results[0].data[1][1], 'Addresses')
        self.assertEqual(results[0].data[1][2].get('name'), 'dup_within_shared')

    def test_dup_in_dg(self):
        test_xml = """\
        <response status="success"><result><config>
          <shared>
            <address>
              <entry name="unique_shared_address"/>
            </address>
            <address-group>
              <entry name="unique_shared_address_group"/>
            </address-group>
          </shared>
          <devices><entry><device-group><entry name="test_dg">
            <address>
              <entry name="dup_within_dg"/>
            </address>
            <address-group>
              <entry name="dup_within_dg"/>
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

        _, _, validator_function = get_policy_validators()['ShadowingAddressesAndGroups']
        results = validator_function(profilepackage)
        self.assertEqual(len(results), 1)
        self.assertEqual(len(results[0].data), 2)
        self.assertEqual(results[0].data[0][0], 'test_dg')
        self.assertEqual(results[0].data[0][1], 'AddressGroups')
        self.assertEqual(results[0].data[0][2].get('name'), 'dup_within_dg')
        self.assertEqual(results[0].data[1][0], 'test_dg')
        self.assertEqual(results[0].data[1][1], 'Addresses')
        self.assertEqual(results[0].data[1][2].get('name'), 'dup_within_dg')


    def test_dups_in_both(self):
        test_xml = """\
        <response status="success"><result><config>
          <shared>
            <address>
              <entry name="unique_shared_address"/>
              <entry name="dup_shared_address_and_dg_address"/>
              <entry name="dup_shared_address_and_dg_addressgroup"/>
            </address>
            <address-group>
              <entry name="unique_shared_address_group"/>
              <entry name="dup_shared_addressgroup_and_dg_address"/>
              <entry name="dup_shared_addressgroup_and_dg_addressgroup"/>
            </address-group>
          </shared>
          <devices><entry><device-group><entry name="test_dg">
            <address>
              <entry name="unique_dg_address"/>
              <entry name="dup_shared_address_and_dg_address"/>
              <entry name="dup_shared_addressgroup_and_dg_address"/>
            </address>
            <address-group>
              <entry name="unique_dg_address_group"/>
              <entry name="dup_shared_address_and_dg_addressgroup"/>
              <entry name="dup_shared_addressgroup_and_dg_addressgroup"/>
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

        _, _, validator_function = get_policy_validators()['ShadowingAddressesAndGroups']
        results = validator_function(profilepackage)

        self.assertEqual(len(results), 4)
        self.assertEqual(len(results[0].data), 2)
        self.assertEqual(results[0].data[0][0], 'test_dg')
        self.assertEqual(results[0].data[0][1], 'Addresses')
        self.assertEqual(results[0].data[0][2].get('name'), 'dup_shared_address_and_dg_address')
        self.assertEqual(results[0].data[1][0], 'shared')
        self.assertEqual(results[0].data[1][1], 'Addresses')
        self.assertEqual(results[0].data[1][2].get('name'), 'dup_shared_address_and_dg_address')
        self.assertEqual(len(results[1].data), 2)
        self.assertEqual(results[1].data[0][0], 'test_dg')
        self.assertEqual(results[1].data[0][1], 'Addresses')
        self.assertEqual(results[1].data[0][2].get('name'), 'dup_shared_addressgroup_and_dg_address')
        self.assertEqual(results[1].data[1][0], 'shared')
        self.assertEqual(results[1].data[1][1], 'AddressGroups')
        self.assertEqual(results[1].data[1][2].get('name'), 'dup_shared_addressgroup_and_dg_address')
        self.assertEqual(len(results[2].data), 2)
        self.assertEqual(results[2].data[0][0], 'test_dg')
        self.assertEqual(results[2].data[0][1], 'AddressGroups')
        self.assertEqual(results[2].data[0][2].get('name'), 'dup_shared_address_and_dg_addressgroup')
        self.assertEqual(results[2].data[1][0], 'shared')
        self.assertEqual(results[2].data[1][1], 'Addresses')
        self.assertEqual(results[2].data[1][2].get('name'), 'dup_shared_address_and_dg_addressgroup')
        self.assertEqual(len(results[3].data), 2)
        self.assertEqual(results[3].data[0][0], 'test_dg')
        self.assertEqual(results[3].data[0][1], 'AddressGroups')
        self.assertEqual(results[3].data[0][2].get('name'), 'dup_shared_addressgroup_and_dg_addressgroup')
        self.assertEqual(results[3].data[1][0], 'shared')
        self.assertEqual(results[3].data[1][1], 'AddressGroups')
        self.assertEqual(results[3].data[1][2].get('name'), 'dup_shared_addressgroup_and_dg_addressgroup')

    def test_shadowing_addresses_and_groups(self):
        test_xml = """\
        <response status="success"><result><config>
          <shared>
            <address>
              <entry name="dup_shared_address_shared_ag_dg_address"/>
            </address>
            <address-group>
              <entry name="dup_shared_address_shared_ag_dg_address"/>
            </address-group>
          </shared>
          <devices><entry><device-group><entry name="test_dg">
            <address>
              <entry name="dup_shared_address_shared_ag_dg_address"/>
            </address>
            <address-group>
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

        _, _, validator_function = get_policy_validators()['ShadowingAddressesAndGroups']
        results = validator_function(profilepackage)

        self.assertEqual(len(results), 2)
        self.assertEqual(len(results[0].data), 2)
        self.assertEqual(results[0].data[0][0], 'shared')
        self.assertEqual(results[0].data[0][1], 'AddressGroups')
        self.assertEqual(results[0].data[0][2].get('name'), 'dup_shared_address_shared_ag_dg_address')
        self.assertEqual(results[0].data[1][0], 'shared')
        self.assertEqual(results[0].data[1][1], 'Addresses')
        self.assertEqual(results[0].data[1][2].get('name'), 'dup_shared_address_shared_ag_dg_address')
        self.assertEqual(len(results[1].data), 3)
        self.assertEqual(results[1].data[0][0], 'test_dg')
        self.assertEqual(results[1].data[0][1], 'Addresses')
        self.assertEqual(results[1].data[0][2].get('name'), 'dup_shared_address_shared_ag_dg_address')
        self.assertEqual(results[1].data[1][0], 'shared')
        self.assertEqual(results[1].data[1][1], 'Addresses')
        self.assertEqual(results[1].data[1][2].get('name'), 'dup_shared_address_shared_ag_dg_address')
        self.assertEqual(results[1].data[2][0], 'shared')
        self.assertEqual(results[1].data[2][1], 'AddressGroups')
        self.assertEqual(results[1].data[2][2].get('name'), 'dup_shared_address_shared_ag_dg_address')


if __name__ == "__main__":
    unittest.main()
