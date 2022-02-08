#!/usr/bin/env python
import collections
import unittest

from palo_alto_firewall_analyzer.core import get_policy_validators
from palo_alto_firewall_analyzer.core import ProfilePackage
from palo_alto_firewall_analyzer.pan_config import PanConfig


class TestUnusedServices(unittest.TestCase):
    @staticmethod
    def create_profilepackage(shared_services, shared_servicegroups, shared_securityprerules, dg_services, dg_securityprerules, dg_natrules):
        device_groups = ["shared"]
        devicegroup_objects = {"shared": collections.defaultdict(list), "test_dg": collections.defaultdict(list)}
        devicegroup_objects['shared']['all_child_device_groups'] = ["shared", "test_dg"]
        devicegroup_objects["shared"]['Services'] = shared_services
        devicegroup_objects["shared"]['ServiceGroups'] = shared_servicegroups
        devicegroup_objects["shared"]['SecurityPreRules'] = shared_securityprerules
        devicegroup_objects["test_dg"]['Services'] = dg_services
        devicegroup_objects["test_dg"]['SecurityPreRules'] = dg_securityprerules
        devicegroup_objects["test_dg"]['NATPreRules'] = dg_natrules

        profilepackage = ProfilePackage(
            panorama='',
            api_key='',
            pan_config=PanConfig('<_/>'),
            mandated_log_profile='',
            allowed_group_profiles=[],
            default_group_profile='',
            ignored_dns_prefixes=[],
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

    def test_unusedservices(self):
        test_xml = """\
        <response status="success"><result><config>
          <shared>
            <service>
              <entry name="service_unused_shared"/>
              <entry name="service_used_nat"/>
              <entry name="service_used_security"/>
              <entry name="service_used_shared"/>
              <entry name="service_used_servicegroup"/>
            </service>
            <service-group>
              <entry name="shared_servicegroup"><members><member>service_used_servicegroup</member></members></entry>
            </service-group>
            <pre-rulebase><security><rules>
              <entry name="shared_rule"><service><member>service_used_shared</member></service></entry>
            </rules></security></pre-rulebase>
          </shared>
          <devices><entry><device-group><entry name="test_dg">
            <service>
              <entry name="service_unused_dg"/>
            </service>
            <pre-rulebase>
              <nat><rules>
                <entry name="nat1"><service>service_used_nat</service></entry>
              </rules></nat>
              <security><rules>
                <entry name="security1"><service><member>service_used_security</member></service></entry>
              </rules></security>    
            </pre-rulebase>
          </entry></device-group></entry></devices>
        </config></result></response>
        """
        pan_config = PanConfig(test_xml)
        shared_services = pan_config.get_devicegroup_object('Services', 'shared')
        shared_servicegroups = pan_config.get_devicegroup_object('ServiceGroups', 'shared')
        shared_securityprerules = pan_config.get_devicegroup_policy('SecurityPreRules', 'shared')
        dg_services = pan_config.get_devicegroup_object('Services', 'test_dg')
        dg_securityprerules = pan_config.get_devicegroup_policy('SecurityPreRules', 'test_dg')
        dg_natrules = pan_config.get_devicegroup_policy('NATPreRules', 'test_dg')
        profilepackage = self.create_profilepackage(shared_services, shared_servicegroups, shared_securityprerules, dg_services, dg_securityprerules, dg_natrules)

        _, _, find_unused_services = get_policy_validators()['UnusedServices']
        results = find_unused_services(profilepackage)
        self.assertEqual(len(results), 1)
        self.assertEqual(len(results[0].data), 1)
        self.assertEqual(results[0].data[0].get('name'), 'service_unused_shared')
        self.assertEqual(results[0].device_group, 'shared')


if __name__ == "__main__":
    unittest.main()
