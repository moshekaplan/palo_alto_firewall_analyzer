#!/usr/bin/env python
import unittest

from palo_alto_firewall_analyzer.core import get_policy_validators
from palo_alto_firewall_analyzer.core import ProfilePackage, ConfigurationSettings
from palo_alto_firewall_analyzer.pan_config import PanConfig


class TestShadowingRules(unittest.TestCase):
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
            no_api=False
        )
        return profilepackage

    def test_shadowingrules(self):
        test_xml = """\
        <response status="success"><result><config>
          <devices><entry><device-group><entry name="test_dg">
            <pre-rulebase><security><rules>
                <entry name="Rule 1">
                  <target><negate>no</negate></target>
                  <to><member>SourceZone</member></to>
                  <from><member>DestZone1</member><member>DestZone2</member></from>
                  <source>
                    <member>address_addressgroup1</member>
                  </source>
                  <destination>
                    <member>ip-127.0.0.3</member>
                  </destination>
                  <source-user><member>any</member></source-user>
                  <category><member>any</member></category>
                  <application><member>dns</member></application>
                  <service><member>tcp-53</member><member>udp-53</member></service>
                  <source-hip><member>any</member></source-hip>
                  <destination-hip><member>any</member></destination-hip>
                </entry>
                <entry name="Rule 2">
                  <target><negate>no</negate></target>
                  <to><member>SourceZone</member></to>
                  <from><member>DestZone1</member></from>
                  <source>
                    <member>ip-127.0.0.1</member>
                  </source>
                  <destination>
                    <member>ip-127.0.0.3</member>
                  </destination>
                  <source-user><member>any</member></source-user>
                  <category><member>any</member></category>
                  <application><member>dns</member></application>
                  <service><member>udp-53</member></service>
                  <source-hip><member>any</member></source-hip>
                  <destination-hip><member>any</member></destination-hip>
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

        _, _, validator_function = get_policy_validators()['ShadowingRules']
        results = validator_function(profilepackage)
        self.assertEqual(len(results), 1)
        self.assertEqual(len(results[0].data), 2)
        self.assertEqual(results[0].data[0][0], 'test_dg')
        self.assertEqual(results[0].data[0][1], 'SecurityPreRules')
        self.assertEqual(results[0].data[0][2], 'Rule 2')
        self.assertEqual(results[0].data[0][3].get('name'), 'Rule 2')
        self.assertEqual(len(results[0].data[1]), 1)
        self.assertEqual(results[0].data[1][0][0], 'test_dg')
        self.assertEqual(results[0].data[1][0][1], 'SecurityPreRules')
        self.assertEqual(results[0].data[1][0][2], 'Rule 1')
        self.assertEqual(results[0].data[1][0][3].get('name'), 'Rule 1')
        self.assertEqual(results[0].device_group, 'test_dg')


if __name__ == "__main__":
    unittest.main()
