#!/usr/bin/env python

import argparse
import os

from palo_alto_firewall_analyzer.pan_api import pan_api
from palo_alto_firewall_analyzer.pan_helpers import load_API_key

DEFAULT_CONFIG_DIR = os.path.expanduser("~\\.pan_policy_analyzer\\")
DEFAULT_API_KEYFILE = DEFAULT_CONFIG_DIR + "API_KEY.txt"


def run_command(firewall, api_key, cmd_type, cmd):
    params = {
        'type': cmd_type,
        'cmd': cmd
    }
    response = pan_api(firewall, method="get", path="/api", params=params, api_key=api_key)
    return response.text


def main():
    parser = argparse.ArgumentParser(description="Run command on a target")
    parser.add_argument("firewall", nargs=1, help="Firewall or Panorama to run on")
    parser.add_argument("type", nargs=1, help="type of command (e.g., op)")
    parser.add_argument("cmd", nargs=1, help="command, (e.g., <operations><show><session><all/></session></show></operations>)")
    parser.add_argument("--api", help=f"File with API Key (default is {DEFAULT_API_KEYFILE})", default=DEFAULT_API_KEYFILE)

    parsed_args = parser.parse_args()
    API_KEY = load_API_key(parsed_args.api)

    firewall = parsed_args.firewall[0]
    cmd_type = parsed_args.type[0]
    cmd = parsed_args.cmd[0]

    print(run_command(firewall, API_KEY, cmd_type, cmd))


if __name__ == '__main__':
    main()
