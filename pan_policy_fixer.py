#!/usr/bin/env python
import argparse
import datetime
import os.path
import sys
import time

# Used to trigger loading the validators and fixers
import palo_alto_firewall_analyzer.validators
import palo_alto_firewall_analyzer.fixers

from palo_alto_firewall_analyzer import pan_api
from palo_alto_firewall_analyzer.core import get_policy_fixers, ConfigurationSettings
from palo_alto_firewall_analyzer.pan_helpers import load_config_package, get_and_save_API_key

DEFAULT_CONFIG_DIR = os.path.expanduser("~\\.pan_policy_analyzer\\")
DEFAULT_CONFIGFILE  = DEFAULT_CONFIG_DIR + "PAN_CONFIG.cfg"
DEFAULT_API_KEYFILE = DEFAULT_CONFIG_DIR + "API_KEY.txt"


###############################################################################
# General helper functions
###############################################################################

def run_policy_fixers(fixers, profilepackage, output_fname):
    problems = {}
    total_problems = 0
    print("Running fixers")

    for name, fixer_values in fixers.items():
        fixer_name, fixer_description, fixer_function = fixer_values
        fixer_problems = fixer_function(profilepackage)
        problems[(fixer_name, fixer_description)] = fixer_problems
        total_problems += len(fixer_problems)

    return problems, total_problems


def write_validator_output(problems, fname, format):
    supported_output_formats = ["text"]
    if format not in supported_output_formats:
        raise Exception(
            f"Unsupported output format of {format}! Output format must be one of {supported_output_formats}")

    if format == 'text':
        with open(fname, 'w') as fh:
            for validator_info, problem_entries in problems.items():
                validator_name, validator_description = validator_info

                fh.write("#" * 80 + '\n')
                fh.write(f"{validator_name}: {validator_description} ({len(problem_entries)})\n")
                fh.write("#" * 80 + '\n')
                for problem_entry in problem_entries:
                    # fh.write(f"Output for config name: {config_name} \n\n")
                    # if validator_problems:
                    fh.write(problem_entry.text + '\n')
                    # else:
                    #    fh.write('(none)\n')
                fh.write('\n')




def main():
    description = """\
Fixes issues in PAN FW policies."""

    fixer_descriptions = '\n'.join(f"{readable_name} - {description}" for readable_name, description, f in
                                       sorted(get_policy_fixers().values()))
    epilog = f"""Here is a detailed list of the {len(get_policy_fixers().keys())} supported fixers:
{fixer_descriptions}
"""

    parser = argparse.ArgumentParser(description=description, epilog=epilog,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--all", help="Run fixer on all Device Groups", action='store_true')
    group.add_argument("--device-group", help="Device Group to run through fixer")
    parser.add_argument("--fixer", help="Fixer to run",
                        choices=sorted(get_policy_fixers().keys()), required=True)
    parser.add_argument("--quiet", help="Silence output", action='store_true')
    parser.add_argument("--config", help=f"Config file to read (default is {DEFAULT_CONFIGFILE})", default=DEFAULT_CONFIGFILE)
    parser.add_argument("--api", help=f"File with API Key (default is {DEFAULT_API_KEYFILE})", default=DEFAULT_API_KEYFILE)
    parser.add_argument("--debug", help="Write all debug output to pan_fixer_debug_YYMMDD_HHMMSS.log", action='store_true')
    parser.add_argument("--limit", help="Limit processing to the first N rules (useful for debugging)", type=int)
    parsed_args = parser.parse_args()

    timestamp_string = datetime.datetime.today().strftime('%Y%m%d_%H%M%S')
    if parsed_args.debug:
        pan_api.set_debug(True, f'pan_fixer_debug_{timestamp_string}.log')

    if not os.path.isfile(parsed_args.config):
        if parsed_args.config == DEFAULT_CONFIGFILE:
            ConfigurationSettings().write_config(parsed_args.config)
            print(f"Config file '{parsed_args.config}' did not exist! Please edit the newly-created config and re-run.")
            sys.exit(1)
        else:
            raise Exception(f"Config file '{parsed_args.config}' does not exist! Exiting")
    configuration_settings = ConfigurationSettings(parsed_args.config).get_config()

    try:
        with open(parsed_args.api) as fh:
            API_KEY = fh.read().strip()
    except OSError:
        print(f"Unable to open file with API key '{parsed_args.api}'")
        API_KEY = get_and_save_API_key(parsed_args.api)

    fixers = {parsed_args.fixer: get_policy_fixers()[parsed_args.fixer]}

    # Build the output string
    if parsed_args.device_group:
        devicegroup_string = "_" + parsed_args.device_group
    else:
        devicegroup_string = ''

    if parsed_args.fixer:
        fixers_string = "_" + parsed_args.fixer
    else:
        fixers_string = ''

    if parsed_args.limit:
        limit_string = "_limit" + str(parsed_args.limit)
    else:
        limit_string = ""

    output_fname = f'pan_fixer_output_{timestamp_string}{devicegroup_string}{fixers_string}{limit_string}.txt'

    verbose = not parsed_args.quiet

    start_time = time.time()
    profilepackage = load_config_package(configuration_settings, API_KEY, parsed_args.device_group,
                                         parsed_args.limit, verbose, False)
    problems, total_problems = run_policy_fixers(fixers, profilepackage, output_fname)
    write_validator_output(problems, output_fname, 'text')
    end_time = time.time()

    print("*" * 80)
    print(f"Full run took {end_time - start_time} seconds")
    print(f"Attempted to fix a total of {total_problems} problems")
    print(f"Detected problems have been written to {output_fname}")

    return


if __name__ == '__main__':
    main()
