#!/usr/bin/env python

import argparse
import os

from palo_alto_firewall_analyzer import pan_api
from palo_alto_firewall_analyzer.pan_helpers import get_and_save_API_key

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
    parser = argparse.ArgumentParser(description="Look up categorization for either a single URL or a file with a list of URLs")
    parser.add_argument("firewall", nargs=1, help="Firewall (not Panorama!) to run on")
    lookup_type = parser.add_mutually_exclusive_group(required=True)
    lookup_type.add_argument("--url", help="URL to look up")
    lookup_type.add_argument("--fpath", help="file with newline-separated list of URLs to look up")
    parser.add_argument("--api", help=f"File with API Key (default is {DEFAULT_API_KEYFILE})", default=DEFAULT_API_KEYFILE)

    parsed_args = parser.parse_args()
    try:
        with open(parsed_args.api) as fh:
            API_KEY = fh.read().strip()
    except OSError:
        print(f"Unable to open file with API key '{parsed_args.api}'")
        API_KEY = get_and_save_API_key(parsed_args.api)

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
