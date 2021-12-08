#!/usr/bin/env python
import collections
import unittest

from palo_alto_firewall_analyzer.core import ProfilePackage
from palo_alto_firewall_analyzer.pan_config import PanConfig
from palo_alto_firewall_analyzer.validators.superseding_rules import find_superseding_rules


class TestSupersedingRules(unittest.TestCase):
    @staticmethod
    def create_profilepackage(rules):
        device_groups = ['test_dg']
        devicegroup_objects = {'test_dg': collections.defaultdict(list)}
        devicegroup_objects["test_dg"]['SecurityPreRules'] = rules

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
            verbose=False
        )
        return profilepackage

    def test_with_mandated_profile(self):
        test_xml = """\
        <response status="success"><result><config>
          <devices><entry><device-group><entry name="test_dg">
            <pre-rulebase><security><rules>
              <entry name="first_rule">
                <from><member>src_zone</member></from>
                <to><member>dest_zone</member></to>
                <source><member>ip-127.0.0.2</member></source>
                <destination><member>ip-127.0.0.3</member></destination>
              </entry>
              <entry name="superseding_rule">
                <from><member>src_zone</member></from>
                <to><member>dest_zone</member></to>
                <source><member>ip-127.0.0.2</member></source>
                <destination>
                  <member>ip-127.0.0.3</member>
                  <member>ip-127.0.0.4</member>
                </destination>
              </entry>
            </rules></security></pre-rulebase>
          </entry></device-group></entry></devices>
        </config></result></response>
        """
        pan_config = PanConfig(test_xml)
        rules = pan_config.get_devicegroup_policy('SecurityPreRules', 'device-group', 'test_dg')

        profilepackage = self.create_profilepackage(rules)
        results = find_superseding_rules(profilepackage)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].data[0][2], 'first_rule')
        self.assertEqual(results[0].data[1][2], 'superseding_rule')


if __name__ == "__main__":
    unittest.main()
