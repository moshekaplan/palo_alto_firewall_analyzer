#!/usr/bin/env python

import argparse
import os

from palo_alto_firewall_analyzer import pan_api
from palo_alto_firewall_analyzer.pan_helpers import load_API_key

DEFAULT_CONFIG_DIR = os.path.expanduser("~" + os.sep + ".pan_policy_analyzer" + os.sep)
DEFAULT_API_KEYFILE = DEFAULT_CONFIG_DIR + "API_KEY.txt"


def main():
    parser = argparse.ArgumentParser(description="Look up categorization for either a single URL or a file with a list of URLs")
    parser.add_argument("firewall", nargs=1, help="Firewall (not Panorama!) to run on")
    lookup_type = parser.add_mutually_exclusive_group(required=True)
    lookup_type.add_argument("--url", help="URL to look up")
    lookup_type.add_argument("--fpath", help="file with newline-separated list of URLs to look up")
    parser.add_argument("--api", help=f"File with API Key (default is {DEFAULT_API_KEYFILE})", default=DEFAULT_API_KEYFILE)

    parsed_args = parser.parse_args()
    API_KEY = load_API_key(parsed_args.api)

    parsed_args = parser.parse_args()

    firewall = parsed_args.firewall[0]

    if parsed_args.url:
        url = parsed_args.url
        categories = pan_api.get_url_categories(firewall, API_KEY, url)
        print(categories)
    elif parsed_args.fpath:
        with open(parsed_args.fpath, encoding="utf8") as fh:
            url_lines = fh.read()
        for url in url_lines.split('\n'):
            url = url.strip()
            if url:
                categories = set(pan_api.get_url_categories(firewall, API_KEY, url.strip()))
                print(f"url={url}, pa_categories={categories}")


if __name__ == '__main__':
    main()
