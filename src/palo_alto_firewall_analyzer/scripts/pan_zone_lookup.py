#!/usr/bin/env python

import argparse
import os

from palo_alto_firewall_analyzer import pan_api
from palo_alto_firewall_analyzer.pan_helpers import load_API_key
from palo_alto_firewall_analyzer.pan_helpers import get_firewall_zone

DEFAULT_CONFIG_DIR = os.path.expanduser("~" + os.sep + ".pan_policy_analyzer" + os.sep)
DEFAULT_API_KEYFILE = DEFAULT_CONFIG_DIR + "API_KEY.txt"


def main():
    parser = argparse.ArgumentParser(description="Look up Zone for a single IP on all firewalls")
    parser.add_argument("panorama", nargs=1, help="Panorama to run on")
    parser.add_argument("ip", nargs=1, help="IP Address to look up")
    parser.add_argument("--api", help=f"File with API Key (default is {DEFAULT_API_KEYFILE})", default=DEFAULT_API_KEYFILE)

    parsed_args = parser.parse_args()
    API_KEY = load_API_key(parsed_args.api)

    panorama = parsed_args.panorama[0]
    firewalls = pan_api.get_active_firewalls(panorama, API_KEY)

    ip = parsed_args.ip[0]
    pad = 15
    print("Firewall".ljust(pad), "Zone".ljust(pad))
    for firewall in firewalls:
        zone = get_firewall_zone(firewall, API_KEY, ip)
        print(firewall.ljust(pad), zone.ljust(pad))


if __name__ == '__main__':
    main()
