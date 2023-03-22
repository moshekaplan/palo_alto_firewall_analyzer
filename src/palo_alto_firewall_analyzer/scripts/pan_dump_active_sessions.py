#!/usr/bin/env python

import argparse
import csv
import os
import xml

import xmltodict

from palo_alto_firewall_analyzer.pan_api import pan_api, export_configuration2
from palo_alto_firewall_analyzer.pan_config import PanConfig
from palo_alto_firewall_analyzer.pan_helpers import load_API_key

DEFAULT_CONFIG_DIR = os.path.expanduser("~\\.pan_policy_analyzer\\")
DEFAULT_API_KEYFILE = DEFAULT_CONFIG_DIR + "API_KEY.txt"


def xml_object_to_dict(xml_obj):
    obj_xml_string = xml.etree.ElementTree.tostring(xml_obj)
    obj_dict = xmltodict.parse(obj_xml_string)
    return obj_dict


def run_command(firewall, api_key, cmd_type, cmd, target_serial=None):
    params = {
        'type': cmd_type,
        'cmd': cmd
    }
    if target_serial:
        params['target'] = target_serial
    response = pan_api(firewall, method="get", path="/api", params=params, api_key=api_key)
    return response.text


def get_serials(panorama, api_key):
    xml_config = export_configuration2(panorama, api_key)
    pan_config = PanConfig(xml_config)
    serials = pan_config.get_managed_serials()
    return serials


def dump_30d_old_active_sessions(panorama, api_key, serials):
    cmd_type = 'op'
    # Sessions must be at least 2592000 seconds old - or 30 days
    # This helps sidestep potentially having too many sessions to be dumped in a single command
    cmd = '<show><session><all></all></session></show>'
    all_sessions = []
    for serial in serials:
        xml_output = run_command(panorama, api_key, cmd_type, cmd, target_serial=serial)
        active_sessions = xmltodict.parse(xml_output)
        if active_sessions['response']['result'] is None:
            continue
        for active_session in active_sessions['response']['result']['entry']:
            session = {}
            if 'security-rule' not in active_session:
                continue
            session['rule'] = active_session['security-rule']
            session['start_time'] = active_session['start-time']
            all_sessions.append(session)
    return all_sessions


def write_sessions_to_csv(fname, sessions):
    with open(fname, 'w', newline='') as csvfile:
        fieldnames = sorted(sessions[0].keys())
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(sessions)


def main():
    parser = argparse.ArgumentParser(description="Run command on a target")
    parser.add_argument("panorama", nargs=1, help="Panorama to run on")
    parser.add_argument("--api", help=f"File with API Key (default is {DEFAULT_API_KEYFILE})", default=DEFAULT_API_KEYFILE)

    parsed_args = parser.parse_args()
    API_KEY = load_API_key(parsed_args.api)

    panorama = parsed_args.panorama[0]

    serials = get_serials(panorama, API_KEY)
    active_sessions = dump_30d_old_active_sessions(panorama, API_KEY, serials)
    write_sessions_to_csv('sessions.csv', active_sessions)


if __name__ == '__main__':
    main()
