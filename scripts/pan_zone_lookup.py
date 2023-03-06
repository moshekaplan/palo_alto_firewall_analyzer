#!/usr/bin/env python

import argparse
import os

from palo_alto_firewall_analyzer import pan_api
from palo_alto_firewall_analyzer.pan_helpers import get_and_save_API_key
from palo_alto_firewall_analyzer.pan_helpers import get_firewall_zone

DEFAULT_CONFIG_DIR = os.path.expanduser("~\\.pan_policy_analyzer\\")
DEFAULT_API_KEYFILE = DEFAULT_CONFIG_DIR + "API_KEY.txt"


def load_api_key(api_file):
    try:
        with open(api_file) as fh:
            api_key = fh.read().strip()
    except OSError:
        print(f"Unable to open file with API key '{api_file}'")
        api_key = get_and_save_API_key(api_file)
    return api_key


def main():
    parser = argparse.ArgumentParser(description="Look up Zone for a single IP on all firewalls")
    parser.add_argument("panorama", nargs=1, help="Panorama to run on")
    parser.add_argument("src", nargs=1, help="IP Address to look up")
    parser.add_argument("--api", help=f"File with API Key (default is {DEFAULT_API_KEYFILE})", default=DEFAULT_API_KEYFILE)

    parsed_args = parser.parse_args()
    try:
        with open(parsed_args.api) as fh:
            API_KEY = fh.read().strip()
    except OSError:
        print(f"Unable to open file with API key '{parsed_args.api}'")
        API_KEY = get_and_save_API_key(parsed_args.api)

    panorama = parsed_args.panorama[0]
    firewalls = pan_api.get_active_firewalls(panorama, API_KEY)

    src_ip = parsed_args.src[0]
    pad = 15
    print("Firewall".ljust(pad), "Zone".ljust(pad))
    for firewall in firewalls:
        zone = get_firewall_zone(firewall, API_KEY, src_ip)
        print(firewall.ljust(pad), zone.ljust(pad))


if __name__ == '__main__':
    main()
