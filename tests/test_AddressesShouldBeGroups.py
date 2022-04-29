#!/usr/bin/env python
import unittest

from palo_alto_firewall_analyzer.core import get_policy_validators
from palo_alto_firewall_analyzer.core import ProfilePackage, ConfigurationSettings
from palo_alto_firewall_analyzer.pan_config import PanConfig


class TestAddressesShouldBeGroups(unittest.TestCase):
    @staticmethod
    def create_profilepackage(pan_config):
        device_groups = ["test_dg"]

        profilepackage = ProfilePackage(
            api_key='',
            pan_config=pan_config,
            settings=ConfigurationSettings().get_config(),
            device_group_hierarchy_children={},
            device_group_hierarchy_parent={},
            device_groups_and_firewalls={},
            device_groups=device_groups,
            devicegroup_objects={},
            devicegroup_exclusive_objects={},
            rule_limit_enabled=False,
            verbose=False,
            no_api=False
        )
        return profilepackage

    def test_replaceableaddresses(self):
        test_xml = """\
        <response status="success"><result><config>
          <devices><entry><device-group><entry name="test_dg">
            <pre-rulebase><security><rules>
              <entry name="source_can_be_group">
                <source>
                  <member>ip-127.0.0.1</member>
                  <member>ip-127.0.0.2</member>
                </source>
                <destination>
                  <member>ip-127.0.0.3</member>
                </destination>
              </entry>
            </rules></security></pre-rulebase>
            <address>
              <entry name="ip-127.0.0.1"><ip-netmask>127.0.0.1</ip-netmask></entry>
              <entry name="ip-127.0.0.2"><ip-netmask>127.0.0.2</ip-netmask></entry>
              <entry name="ip-127.0.0.3"><ip-netmask>127.0.0.3</ip-netmask></entry>
            </address>
            <address-group>
              <entry name="address_addressgroup1"><static><member>ip-127.0.0.1</member><member>ip-127.0.0.2</member></static></entry>
            </address-group>
          </entry></device-group></entry></devices>
          <readonly><devices><entry name="localhost.localdomain"><device-group>
            <entry name="test_dg"><id>11</id></entry>
          </device-group></entry></devices></readonly>
        </config></result></response>
        """
        pan_config = PanConfig(test_xml)
        profilepackage = self.create_profilepackage(pan_config)

        _, _, validator_function = get_policy_validators()['AddressesShouldBeGroups']
        results = validator_function(profilepackage)
        self.assertEqual(len(results), 1)
        self.assertEqual(len(results[0].data), 3)
        self.assertEqual(results[0].data[0], 'SecurityPreRules')
        self.assertEqual(results[0].data[1].get('name'), 'source_can_be_group')
        self.assertEqual(results[0].data[2], {'source': 'address_addressgroup1'})
        self.assertEqual(results[0].device_group, 'test_dg')


if __name__ == "__main__":
    unittest.main()
