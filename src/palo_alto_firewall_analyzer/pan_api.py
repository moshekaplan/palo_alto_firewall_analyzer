import collections
import functools
import json
import logging
import xml.etree.ElementTree

import requests
import urllib
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger(__name__)

###############################################################################
# API functions
###############################################################################

def pan_api(firewall, method, path, params, api_key=None, data=None):
    url = "https://{hostname}{path}".format(hostname=firewall, path=path)
    headers = {}
    if api_key:
        headers['X-PAN-KEY'] = api_key

    # Try 3 times, in case of weird issues where the API responds 200, but with no data:
    for i in range(3):
        response = requests.request(method, url, params=params, headers=headers, data=data, verify=False)
        logger.debug(response.url)
        logger.debug(response.status_code)
        logger.debug(response.text)
        if response.text:
            break
        logger.debug("Error: No content! Retry count: f{i+1}")
    else:
        raise Exception("API request failed 3 times!")
    response.raise_for_status()
    return response


###############################################################################
# XML API functions
###############################################################################
def get_API_key(panorama, username, password):
    params = {
        'type': 'keygen',
        'user': username,
        'password': password
    }
    response = pan_api(panorama, method="get", path="/api", params=params)

    root = xml.etree.ElementTree.fromstring(response.text)
    for leaf in root.iter():
        if leaf.tag == "key":
            api_key = leaf.text
            break
    else:
        raise Exception("API key not found in response! " + response.text)

    return api_key


@functools.lru_cache(maxsize=None)
def validate_commit(firewall, api_key):
    params = {
        'type': 'op',
        'cmd': "<validate><full></full></validate>",
    }

    response = pan_api(firewall, method="get", path="/api", params=params, api_key=api_key)

    return response.text


@functools.lru_cache(maxsize=None)
def export_configuration(firewall, api_key):
    params = {
        'type': 'export',
        'category': "configuration",
    }

    response = pan_api(firewall, method="get", path="/api", params=params, api_key=api_key)

    return response.text


@functools.lru_cache(maxsize=None)
def export_configuration2(firewall, api_key):
    params = {
        'type': 'config',
        'category': "show",
    }

    response = pan_api(firewall, method="get", path="/api", params=params, api_key=api_key)

    return response.text


@functools.lru_cache(maxsize=None)
def get_interface(firewall, api_key, ip):
    params = {
        'type': 'op',
        'cmd': "<test><routing><fib-lookup><ip>" + ip + "</ip><virtual-router>Default-VR</virtual-router></fib-lookup></routing></test>"
    }

    response = pan_api(firewall, method="get", path="/api", params=params, api_key=api_key)

    root = xml.etree.ElementTree.fromstring(response.text)
    for leaf in root.iter():
        if leaf.tag == "interface":
            interface = leaf.text
            break
    else:
        raise Exception(f"Interface info not found in XML response on firewall {firewall} for {ip}! " + response.text)

    return interface


@functools.lru_cache(maxsize=None)
def get_interface_zone(firewall, api_key, interface):
    params = {
        'type': 'op',
        'cmd': '<show><interface>' + interface + '</interface></show>'
    }

    response = pan_api(firewall, method="get", path="/api", params=params, api_key=api_key)

    root = xml.etree.ElementTree.fromstring(response.text)
    for leaf in root.iter():
        if leaf.tag == "zone":
            zone = leaf.text
            break
    else:
        raise Exception(
            f"Zone info not found in XML response on firewall {firewall} for interface {interface}! " + response.text)

    return zone


@functools.lru_cache(maxsize=None)
def get_device_groups_and_firewalls(panorama, api_key):
    """Returns a mapping of device groups to associated firewall hostnames"""
    params = {
        'type': 'op',
        'cmd': '<show><devicegroups/></show>'
    }
    response = pan_api(panorama, method="get", path="/api", params=params, api_key=api_key)

    devicegroups = {'shared': []}
    root = xml.etree.ElementTree.fromstring(response.text)
    for devicegroup_elem in root.findall('./result/devicegroups/entry'):
        device_group_name = devicegroup_elem.get('name')
        firewalls = [hostname_elem.text for hostname_elem in devicegroup_elem.findall('./devices/entry/hostname')]
        devicegroups[device_group_name] = firewalls

    return devicegroups


@functools.lru_cache(maxsize=None)
def get_device_groups_hierarchy(panorama, api_key):
    params = {
        'type': 'config',
        'action': 'get',
        'xpath': "/config/readonly/devices/entry[@name='localhost.localdomain']/device-group"
    }
    response = pan_api(panorama, method="get", path="/api", params=params, api_key=api_key)

    root = xml.etree.ElementTree.fromstring(response.text)
    device_group_hierarchy_children = collections.defaultdict(list)
    device_group_hierarchy_parent = {}
    for devicegroup_elem in (root.findall('./result/device-group/entry')):
        name = devicegroup_elem.get('name')
        parent = devicegroup_elem.find('parent-dg')
        if parent is not None:
            device_group_hierarchy_children[parent.text].append(name)
            device_group_hierarchy_parent[name] = parent.text

    # The Device Group with a child, but no parents must be the root Device Group
    shared_child = list(set(device_group_hierarchy_children.keys()) - set(device_group_hierarchy_parent.keys()))[0]
    device_group_hierarchy_children['shared'] = [shared_child]
    device_group_hierarchy_parent[shared_child] = 'shared'

    return device_group_hierarchy_children, device_group_hierarchy_parent


@functools.lru_cache(maxsize=None)
def get_active_firewalls(panorama, api_key):
    params = {
        'type': 'op',
        'cmd': '<show><devices><all></all></devices></show>'
    }
    response = pan_api(panorama, method="get", path="/api", params=params, api_key=api_key)

    active_devices = []
    root = xml.etree.ElementTree.fromstring(response.text)
    for device_elem in root.findall('./result/devices/entry'):
        hostname = device_elem.find('hostname').text
        state_elem = device_elem.find('ha/state')
        if state_elem is None or state_elem.text == 'active':
            active_devices.append(hostname)
    return sorted(active_devices)


@functools.lru_cache(maxsize=None)
def get_url_categories(firewall, api_key, url):
    params = {
        'type': 'op',
        'cmd': "<test><url>" + urllib.parse.quote(url) + "</url></test>",
    }
    response = pan_api(firewall, method="get", path="/api", params=params, api_key=api_key)

    categories = []
    root = xml.etree.ElementTree.fromstring(response.text)
    basedb_response, clouddb_response = root.findall('./result')[0].text.strip().split('\n')

    _, *categories = clouddb_response.split(' (')[0].split(' ')
    return categories

###############################################################################
# REST API functions
###############################################################################


SUPPORTED_POLICY_TYPES = (
    "SecurityPreRules", "SecurityPostRules",
    "NATPreRules", "NATPostRules",
    "QoSPreRules", "QoSPostRules",
    "PolicyBasedForwardingPreRules", "PolicyBasedForwardingPostRules",
    "DecryptionPreRules", "DecryptionPostRules",
    "TunnelInspectionPreRules", "TunnelInspectionPostRules",
    "ApplicationOverridePreRules", "ApplicationOverridePostRules",
    "AuthenticationPreRules", "AuthenticationPostRules",
    "DoSPreRules", "DoSPostRules",
    "SDWANPreRules", "SDWANPostRules"
)

SUPPORTED_OBJECT_TYPES = (
    "Addresses",
    "AddressGroups",
    # "Regions",
    # "DynamicUserGroups",
    "Applications",
    "ApplicationGroups",
    # "ApplicationFilters",
    "CustomURLCategories",
    "Services",
    "ServiceGroups",
    # "Tags",
    # "GlobalProtectHIPObjects",
    # "GlobalProtectHIPProfiles",
    # "ExternalDynamicLists",
    # "CustomDataPatterns",
    # "CustomSpywareSignatures",
    # "CustomVulnerabilitySignatures",
    # "CustomURLCategories",
    "AntivirusSecurityProfiles",
    # "AntiSpywareSecurityProfiles",
    # "VulnerabilityProtectionSecurityProfiles",
    # "URLFilteringSecurityProfiles",
    # "FileBlockingSecurityProfiles",
    # "WildFireAnalysisSecurityProfiles",
    # "DataFilteringSecurityProfiles",
    # "DoSProtectionSecurityProfiles",
    # "GTPProtectionSecurityProfiles",
    # "SCTPProtectionSecurityProfiles",
    "SecurityProfileGroups",
    # "LogForwardingProfiles",
    # "AuthenticationEnforcements",
    # "DecryptionProfiles",
    # "DecryptionForwardingProfiles",
    # "SDWANPathQualityProfiles",
    # "SDWANTrafficDistributionProfiles",
    # "Schedules",
)

SUPPORTED_LOCATION_TYPES = ('shared', 'device-group')


def get_object(panorama, version, api_key, object_type, device_group):
    '''Retrieve all objects of a particular type via the REST API'''
    if object_type not in SUPPORTED_OBJECT_TYPES:
        raise Exception(f"Invalid object_type '{object_type}' ! object_type must be one of {SUPPORTED_OBJECT_TYPES}")

    # 'shared' is a reserved name by PA and not allowed to be used as a device group name
    if device_group == 'shared':
        location_type = 'shared'
    else:
        location_type = 'device-group'

    path = f"/restapi/v{version}/Objects/{object_type}"
    params = {
        'location': location_type,
        'output-format': 'json',
    }
    if location_type == 'device-group':
        params['device-group'] = device_group

    response = pan_api(panorama, method="get", path=path, params=params, api_key=api_key)
    return response.json()


def delete_object(panorama, version, api_key, object_type, object_to_delete, device_group):
    if object_type not in SUPPORTED_OBJECT_TYPES:
        raise Exception(f"Invalid object_type '{object_type}' ! object_type must be one of {SUPPORTED_OBJECT_TYPES}")

    # 'shared' is a reserved name by PA and not allowed to be used as a device group name
    if device_group == 'shared':
        location_type = 'shared'
    else:
        location_type = 'device-group'
    assert location_type in SUPPORTED_LOCATION_TYPES

    path = f"/restapi/v{version}/Objects/{object_type}"
    params = {
        'location': location_type,
        'output-format': 'json',
    }
    if location_type == 'device-group':
        params['device-group'] = device_group

    params['name'] = object_to_delete
    response = pan_api(panorama, method="delete", path=path, params=params, api_key=api_key)
    return response.json()


def rename_object(panorama, version, api_key, objecttype, old_name, new_name, device_group):
    if objecttype not in (SUPPORTED_OBJECT_TYPES):
        raise Exception(f"Invalid policytype '{objecttype}' ! polictype must be one of {SUPPORTED_OBJECT_TYPES}")

    # 'shared' is a reserved name by PA and not allowed to be used as a device group name
    if device_group == 'shared':
        location_type = 'shared'
    else:
        location_type = 'device-group'
    assert location_type in SUPPORTED_LOCATION_TYPES

    path = f"/restapi/v{version}/Objects/{objecttype}:rename"
    params = {
        'output-format': 'json',
        'location': location_type,
        'name': old_name,
        'newname': new_name,
    }

    if location_type == 'device-group':
        params['device-group'] = device_group
    response = pan_api(panorama, method="post", path=path, params=params, api_key=api_key)
    return response.json()


def delete_policy(panorama, version, api_key, policy_type, policy_name, device_group):
    if policy_type not in SUPPORTED_POLICY_TYPES:
        raise Exception(f"Invalid policy_type '{policy_type}' ! polictype must be one of {SUPPORTED_POLICY_TYPES}")

    # 'shared' is a reserved name by PA and not allowed to be used as a device group name
    if device_group == 'shared':
        location_type = 'shared'
    else:
        location_type = 'device-group'
    assert location_type in SUPPORTED_LOCATION_TYPES

    path = f"/restapi/v{version}/Policies/{policy_type}"
    params = {
        'location': location_type,
        'output-format': 'json'
    }
    if location_type == 'device-group':
        params['device-group'] = device_group

    params['name'] = policy_name
    response = pan_api(panorama, method="delete", path=path, params=params, api_key=api_key)
    return response.json()


def update_devicegroup_policy(panorama, version, api_key, policy, policytype, device_group):
    if policytype not in SUPPORTED_POLICY_TYPES:
        raise Exception(f"Invalid policytype '{policytype}' ! polictype must be one of {SUPPORTED_POLICY_TYPES}")

    # 'shared' is a reserved name by PA and not allowed to be used as a device group name
    if device_group == 'shared':
        location_type = 'shared'
    else:
        location_type = 'device-group'
    assert location_type in SUPPORTED_LOCATION_TYPES

    path = f"/restapi/v{version}/Policies/{policytype}"
    params = {
        'output-format': 'json',
        'location': location_type
    }

    if location_type == 'device-group':
        params['device-group'] = device_group

    params['name'] = policy['@name']
    data = json.dumps({'entry': [policy]})

    response = pan_api(panorama, method="put", path=path, params=params, data=data, api_key=api_key)

    return response.json()


def update_devicegroup_object(panorama, version, api_key, object_entry, objecttype, device_group):
    if objecttype not in SUPPORTED_OBJECT_TYPES:
        raise Exception(f"Invalid objecttype '{objecttype}'! objecttype must be one of {SUPPORTED_OBJECT_TYPES}")

    # 'shared' is a reserved name by PA and not allowed to be used as a device group name
    if device_group == 'shared':
        location_type = 'shared'
    else:
        location_type = 'device-group'
    assert location_type in SUPPORTED_LOCATION_TYPES

    path = f"/restapi/v{version}/Objects/{objecttype}"
    params = {
        'output-format': 'json',
        'location': location_type
    }

    if location_type == 'device-group':
        params['device-group'] = device_group

    params['name'] = object_entry['@name']
    data = json.dumps({'entry': [object_entry]})

    response = pan_api(panorama, method="put", path=path, params=params, data=data, api_key=api_key)

    return response.json()

##################################################
# Note: The following functions need to be retested prior to use
##################################################


def create_object(panorama, version, api_key, object_type, object_to_create, locationtype, device_group=None):
    allowed_locationtypes = ['shared', 'device-group']
    if locationtype not in allowed_locationtypes:
        raise Exception(
            f"Unsupported locationtype of {locationtype}! locationtype must be one of {allowed_locationtypes}")

    path = f"/restapi/v{version}/Objects/{object_type}"

    params = {
        'output-format': 'json',
        'location': locationtype
    }

    if locationtype == 'device-group':
        params['device-group'] = device_group

    params['name'] = object_to_create['@name']

    data = json.dumps({'entry': [object_to_create]})

    response = pan_api(panorama, method="post", path=path, params=params, data=data, api_key=api_key)
    return response.json()


# Test code:
def main():
    with open("API_KEY.txt") as fh:
        API_KEY = fh.read().strip()

    import configparser
    validator_config = configparser.ConfigParser()
    validator_config.read("PAN_CONFIG.cfg")
    config_profile = validator_config.sections()[0]
    panorama = validator_config[config_profile]['Panorama']

    config = export_configuration2(panorama, API_KEY).text
    with open('config_pretty.xml', 'w') as fh:
        fh.write(config)


if __name__ == "__main__":
    main()
