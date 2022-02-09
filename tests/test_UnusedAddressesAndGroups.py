#!/usr/bin/env python
import collections
import unittest

from palo_alto_firewall_analyzer.core import get_policy_validators
from palo_alto_firewall_analyzer.core import ProfilePackage, ConfigurationSettings
from palo_alto_firewall_analyzer.pan_config import PanConfig


class TestUnusedAddressesAndGroups(unittest.TestCase):
    @staticmethod
    def create_profilepackage(shared_addresses, shared_addressgroups, shared_securityprerules, shared_natprerules, dg_addresses, dg_securityprerules):
        device_groups = ["shared"]
        devicegroup_objects = {"shared": collections.defaultdict(list), "test_dg": collections.defaultdict(list)}
        devicegroup_objects['shared']['all_child_device_groups'] = ["shared", "test_dg"]
        devicegroup_objects["shared"]['Addresses'] = shared_addresses
        devicegroup_objects["shared"]['AddressGroups'] = shared_addressgroups
        devicegroup_objects["shared"]['SecurityPreRules'] = shared_securityprerules
        devicegroup_objects["shared"]['NATPreRules'] = shared_natprerules
        devicegroup_objects["test_dg"]['SecurityPreRules'] = dg_addresses
        devicegroup_objects["test_dg"]['NATPreRules'] = dg_securityprerules

        profilepackage = ProfilePackage(
            api_key='',
            pan_config=PanConfig('<_/>'),
            settings=ConfigurationSettings().get_config(),
            device_group_hierarchy_children={},
            device_group_hierarchy_parent={},
            device_groups_and_firewalls={},
            device_groups=device_groups,
            devicegroup_objects=devicegroup_objects,
            devicegroup_exclusive_objects={},
            rule_limit_enabled=False,
            verbose=False,
            no_api=False
        )
        return profilepackage

    def test_unusedaddresses(self):
        test_xml = """\
        <response status="success"><result><config>
          <shared>
            <address>
              <entry name="address_unused"/>
              <entry name="address_used_addressgroup"/>
              <entry name="address_used_security"/>
              <entry name="address_used_in_nat1"/>
              <entry name="address_used_in_dg"/>
            </address>
            <address-group>
              <entry name="addressgroup1"><static><member>address_used_addressgroup</member></static></entry>
            </address-group>
            <pre-rulebase>
              <security><rules>
                <entry name="shared_rule1"><source><member>address_used_security</member></source></entry>
                <entry name="shared_rule2"><destination><member>addressgroup1</member></destination></entry>
              </rules></security>
              <nat><rules>
                <entry name="nat1"><source-translation><translated-address>address_used_in_nat1</translated-address></source-translation></entry>
              </rules></nat>
            </pre-rulebase>
          </shared>
          <devices><entry><device-group><entry name="test_dg">
            <address>
              <entry name="service_unused_dg"/>
            </address>
            <pre-rulebase>
              <security><rules>
                <entry name="shared_rule"><source><member>address_used_in_dg</member></source></entry>
              </rules></security>
            </pre-rulebase>
          </entry></device-group></entry></devices>
        </config></result></response>
        """
        pan_config = PanConfig(test_xml)
        shared_addresses = pan_config.get_devicegroup_object('Addresses', 'shared')
        shared_addressgroups = pan_config.get_devicegroup_object('AddressGroups', 'shared')
        shared_securityprerules = pan_config.get_devicegroup_policy('SecurityPreRules', 'shared')
        shared_natprerules = pan_config.get_devicegroup_policy('NATPreRules', 'shared')
        dg_addresses = pan_config.get_devicegroup_object('Addresses', 'test_dg')
        dg_securityprerules = pan_config.get_devicegroup_policy('SecurityPreRules', 'test_dg')

        profilepackage = self.create_profilepackage(shared_addresses, shared_addressgroups, shared_securityprerules, shared_natprerules, dg_addresses, dg_securityprerules)

        _, _, validator_function = get_policy_validators()['UnusedAddresses']
        results = validator_function(profilepackage)

        self.assertEqual(len(results), 1)
        self.assertEqual(len(results[0].data), 1)
        self.assertEqual(results[0].data[0].get('name'), 'address_unused')
        self.assertEqual(results[0].device_group, 'shared')


if __name__ == "__main__":
    unittest.main()
