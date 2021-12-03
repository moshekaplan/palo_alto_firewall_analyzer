#!/usr/bin/env python
import argparse
import configparser
import datetime
import time

import palo_alto_firewall_analyzer.validators

from palo_alto_firewall_analyzer import pan_api
from palo_alto_firewall_analyzer.core import get_policy_validators
from palo_alto_firewall_analyzer.pan_api_helpers import load_config_package, get_and_save_API_key

DEFAULT_API_KEYFILE = "API_KEY.txt"



###############################################################################
# General helper functions
###############################################################################



def run_policy_validators(validators, profilepackage, output_fname):
    problems = {}
    total_problems = 0
    print("Running validators")

    for name, validator_values in validators.items():
        validator_name, validator_description, validator_function = validator_values
        validator_problems = validator_function(profilepackage)
        problems[(validator_name, validator_description)] = validator_problems
        total_problems += len(validator_problems)

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
    description = f"""\
Retrieves PAN FW policy and checks it for various issues."""

    validator_descriptions = '\n'.join(f"{readable_name} - {description}" for readable_name, description, f in
                                       sorted(get_policy_validators().values()))
    epilog = f"""Here is a detailed list of the {len(get_policy_validators().keys())} supported validators:
{validator_descriptions}
"""

    parser = argparse.ArgumentParser(description=description, epilog=epilog,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--all", help="Run validator for all Device Groups", action='store_true')
    group.add_argument("--device-group", help="Device Group to run through validator")
    parser.add_argument("--validator", help="Only run specified validator",
                        choices=sorted(get_policy_validators().keys()))
    parser.add_argument("--quiet", help="Silence output", action='store_true')
    parser.add_argument("--config", help="Config file to read", default="PAN_CONFIG.cfg")
    parser.add_argument("--profile", help="Config profile to run through validator (defaults to first config entry)")
    parser.add_argument("--api", help="File with API Key", default=DEFAULT_API_KEYFILE)
    parser.add_argument("--debug", help="Write all debug output to pan_validator_debug.log", action='store_true')
    parser.add_argument("--limit", help="Limit processing to the first N rules (useful for debugging)", type=int)
    parsed_args = parser.parse_args()

    if parsed_args.debug:
        pan_api.set_debug(True, 'pan_validator_debug.log')

    validator_config = configparser.ConfigParser()
    validator_config.read(parsed_args.config)

    if parsed_args.profile:
        config_profile = parsed_args.profile
    elif len(validator_config.sections()) == 1:
        config_profile = validator_config.sections()[0]
    else:
        if len(validator_config.sections()) == 0:
            raise Exception(
                f"Unable to parse config file '{parsed_args.config}'! Specify the profile with --profile")
        else:
            raise Exception(
                f"More than one configuration profile is available in '{parsed_args.config}'! Specify the profile with --profile")

    try:
        with open(parsed_args.api) as fh:
            API_KEY = fh.read().strip()
    except OSError:
        print(f"Unable to open file with API key '{parsed_args.api}'")
        API_KEY = get_and_save_API_key(parsed_args.api)

    if parsed_args.validator:
        validators = {parsed_args.validator: get_policy_validators()[parsed_args.validator]}
    else:
        validators = get_policy_validators()

    # Build the output string
    timestamp_string = datetime.datetime.today().strftime('%Y%m%d_%H%M%S')

    if parsed_args.device_group:
        devicegroup_string = "_" + parsed_args.device_group
    else:
        devicegroup_string = ''

    if parsed_args.validator:
        validators_string = "_" + parsed_args.validator
    else:
        validators_string = ''

    if parsed_args.limit:
        limit_string = "_limit" + str(parsed_args.limit)
    else:
        limit_string = ""

    output_fname = f'pan_policy_validator_output_{timestamp_string}_{config_profile}{devicegroup_string}{validators_string}{limit_string}.txt'

    verbose = not parsed_args.quiet

    start_time = time.time()
    profilepackage = load_config_package(validator_config[config_profile], API_KEY, parsed_args.device_group,
                                         parsed_args.limit, verbose)
    problems, total_problems = run_policy_validators(validators, profilepackage, output_fname)
    write_validator_output(problems, output_fname, 'text')
    end_time = time.time()

    print("*" * 80)
    print(f"Full run took {end_time - start_time} seconds")
    print(f"Detected a total of {total_problems} problems")

    return


if __name__ == '__main__':
    main()
