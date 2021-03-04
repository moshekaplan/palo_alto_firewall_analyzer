#!/usr/bin/env python
import unittest

from palo_alto_firewall_analyzer.core import ProfilePackage
from palo_alto_firewall_analyzer.pan_config import PanConfig
from palo_alto_firewall_analyzer.validators.find_equivalent_objects import find_equivalent_addresses
from palo_alto_firewall_analyzer.validators.find_equivalent_objects import find_equivalent_services


class TestEquivalentObjects(unittest.TestCase):
    @staticmethod
    def create_profilepackage(shared_addresses, dg_addresses, shared_services, dg_services):
        device_groups = ["test_dg"]
        device_group_hierarchy_parent = {"test_dg": "shared"}
        devicegroup_objects = {"shared": {}, "test_dg": {}}
        devicegroup_objects["shared"]['Addresses'] = shared_addresses
        devicegroup_objects["test_dg"]['Addresses'] = dg_addresses
        devicegroup_objects["shared"]['Services'] = shared_services
        devicegroup_objects["test_dg"]['Services'] = dg_services

        profilepackage = ProfilePackage(
            panorama='',
            version='',
            api_key='',
            pan_config=PanConfig('<_/>'),
            mandated_log_profile='',
            allowed_group_profiles=[],
            default_group_profile='',
            ignored_dns_prefixes=[],
            device_group_hierarchy_children={},
            device_group_hierarchy_parent=device_group_hierarchy_parent,
            device_groups_and_firewalls={},
            device_groups=device_groups,
            devicegroup_objects=devicegroup_objects,
            devicegroup_exclusive_objects={},
            rule_limit_enabled=False,
            verbose=False
        )
        return profilepackage

    def test_equivalent_addresses(self):
        test_xml = """\
        <response status="success"><result><config>
          <shared>
            <address>
              <entry name="unique_netmask"><ip-netmask>ignored.tld</ip-netmask></entry>
              <entry name="dup_fqdn1"><fqdn>dupfqdn.tld</fqdn></entry>
              <entry name="dup_fqdn2"><fqdn>dupfqdn.tld</fqdn></entry>
            </address>
          </shared>
          <devices><entry><device-group><entry name="test_dg">
            <address>
              <entry name="unique_fqdn"><ip-netmask>unique.tld</ip-netmask></entry>
              <entry name="dup_fqdn3"><fqdn>dupfqdn.tld</fqdn></entry>
            </address>
          </entry></device-group></entry></devices>
        </config></result></response>
        """
        pan_config = PanConfig(test_xml)
        shared_addresses = pan_config.get_devicegroup_object('Addresses', 'shared')
        dg_addresses = pan_config.get_devicegroup_object('Addresses', 'device-group', 'test_dg')
        profilepackage = self.create_profilepackage(shared_addresses, dg_addresses, [], [])
        results = find_equivalent_addresses(profilepackage)
        self.assertEqual(len(results), 1)
        self.assertEqual(len(results[0].data), 3)
        self.assertEqual(results[0].data[0][0], 'shared')
        self.assertEqual(results[0].data[0][1].get('name'), 'dup_fqdn1')
        self.assertEqual(results[0].data[1][0], 'shared')
        self.assertEqual(results[0].data[1][1].get('name'), 'dup_fqdn2')
        self.assertEqual(results[0].data[2][0], 'test_dg')
        self.assertEqual(results[0].data[2][1].get('name'), 'dup_fqdn3')

    def test_equivalent_services(self):
        test_xml = """\
        <response status="success"><result><config>
          <shared>
            <service>
              <entry name="tcp-nondup1"><protocol><tcp><port>1</port><override><no/></override></tcp></protocol></entry>
              <entry name="tcp-dup1"><protocol><tcp><port>2</port><override><no/></override></tcp></protocol></entry>
              <entry name="tcp-dup2"><protocol><tcp><port>2</port><override><no/></override></tcp></protocol></entry>
            </service>
          </shared>
          <devices><entry><device-group><entry name="test_dg">
            <service>
              <entry name="tcp-dup3"><protocol><tcp><port>2</port><override><no/></override></tcp></protocol></entry>
              <entry name="tcp-nondup2"><protocol><tcp><port>1</port><override><yes/></override></tcp></protocol></entry>
            </service>
          </entry></device-group></entry></devices>
        </config></result></response>
        """
        pan_config = PanConfig(test_xml)
        shared_services = pan_config.get_devicegroup_object('Services', 'shared')
        dg_services = pan_config.get_devicegroup_object('Services', 'device-group', 'test_dg')
        profilepackage = self.create_profilepackage([], [], shared_services, dg_services)

        results = find_equivalent_services(profilepackage)
        self.assertEqual(len(results), 1)
        self.assertEqual(len(results[0].data), 3)
        self.assertEqual(results[0].data[0][0], 'shared')
        self.assertEqual(results[0].data[0][1].get('name'), 'tcp-dup1')
        self.assertEqual(results[0].data[1][0], 'shared')
        self.assertEqual(results[0].data[1][1].get('name'), 'tcp-dup2')
        self.assertEqual(results[0].data[2][0], 'test_dg')
        self.assertEqual(results[0].data[2][1].get('name'), 'tcp-dup3')


if __name__ == "__main__":
    unittest.main()
