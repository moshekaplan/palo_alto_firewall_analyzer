#!/usr/bin/env python
import argparse
import datetime
import logging
import os.path
import sys
import time

# Note that this triggers loading the validators
import palo_alto_firewall_analyzer.validators

from palo_alto_firewall_analyzer.core import get_policy_validators, ConfigurationSettings
from palo_alto_firewall_analyzer.pan_helpers import load_config_package, get_and_save_API_key

DEFAULT_CONFIG_DIR = os.path.expanduser("~\\.pan_policy_analyzer\\")
DEFAULT_CONFIGFILE  = DEFAULT_CONFIG_DIR + "PAN_CONFIG.cfg"
DEFAULT_API_KEYFILE = DEFAULT_CONFIG_DIR + "API_KEY.txt"
EXECUTION_START_TIME = datetime.datetime.today().strftime('%Y%m%d_%H%M%S')

logger = logging.getLogger('palo_alto_firewall_analyzer')

###############################################################################
# General helper functions
###############################################################################
def configure_logging(enable_debug_log, console_enabled):
    logger.setLevel(logging.DEBUG)
    formatter = logging.Formatter('%(name)s - %(levelname)s - %(message)s')

    if enable_debug_log:
        logfile_path = f'pan_validator_debug_{EXECUTION_START_TIME}.log'
        fh = logging.FileHandler(logfile_path)
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(formatter)
        logger.addHandler(fh)

    if console_enabled:
        ch = logging.StreamHandler()
        ch.setLevel(logging.INFO)
        ch.setFormatter(formatter)
        logger.addHandler(ch)


def run_policy_validators(validators, profilepackage, output_fname):
    problems = {}
    total_problems = 0
    logger.info("Running validators")

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


def load_api_key(api_file):
    try:
        with open(api_file) as fh:
            api_key = fh.read().strip()
    except OSError:
        logger.error(f"Unable to open file with API key '{api_file}'")
        api_key = get_and_save_API_key(api_file)
    return api_key


def main():
    description = """\
Retrieves PAN FW policy and checks it for various issues."""

    validator_descriptions = '\n'.join(f"{readable_name} - {description}" for readable_name, description, f in
                                       sorted(get_policy_validators().values()))
    epilog = f"""Here is a detailed list of the {len(get_policy_validators().keys())} supported validators:
{validator_descriptions}
"""

    parser = argparse.ArgumentParser(description=description, epilog=epilog,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--all", help="Run validators on all Device Groups", action='store_true')
    group.add_argument("--device-group", help="Device Group to run through validator")
    parser.add_argument("--validator", help="Only run specified validators (repeat for multiple)",
                        choices=sorted(get_policy_validators().keys()), action='append')
    parser.add_argument("--quiet", help="Silence output", action='store_true')
    parser.add_argument("--config", help=f"Config file to read (default is {DEFAULT_CONFIGFILE})", default=DEFAULT_CONFIGFILE)
    parser.add_argument("--api", help=f"File with API Key (default is {DEFAULT_API_KEYFILE})", default=DEFAULT_API_KEYFILE)
    parser.add_argument("--no-api", help="Skip validators that require making API requests", action='store_true')
    parser.add_argument("--xml", help="Process an XML file from 'Export Panorama configuration version'. This does not use an API key and implies --no-api")
    parser.add_argument("--debug", help="Write all debug output to pan_validator_debug_YYMMDD_HHMMSS.log", action='store_true')
    parser.add_argument("--limit", help="Limit processing to the first N rules (useful for debugging)", type=int)
    parsed_args = parser.parse_args()

    configure_logging(parsed_args.debug, not parsed_args.quiet)
    logger.debug(f"Script launched with the following arguments {' '.join(sys.argv)}")
    if parsed_args.xml:
        api_key = ''
        parsed_args.no_api = True
        xml_string = "_xml"
    else:
        api_key = load_api_key(parsed_args.api)
        xml_string = ''

    if parsed_args.validator:
        validators = {validator: get_policy_validators()[validator] for validator in parsed_args.validator}
    else:
        validators = get_policy_validators()

    # Build the output string
    if parsed_args.device_group:
        devicegroup_string = "_" + parsed_args.device_group
    else:
        devicegroup_string = ''

    if parsed_args.validator:
        validators_string = "_" + "_".join(sorted(parsed_args.validator))
    else:
        validators_string = ''

    if parsed_args.limit:
        limit_string = "_limit" + str(parsed_args.limit)
    else:
        limit_string = ""

    if parsed_args.no_api:
        no_api_string = "_noapi"
    else:
        no_api_string = ""

    output_fname = f'pan_analyzer_output_{EXECUTION_START_TIME}{devicegroup_string}{xml_string}{no_api_string}{validators_string}{limit_string}.txt'
    logger.debug(f"Writing output to {output_fname}")

    no_api = parsed_args.no_api

    if not os.path.isfile(parsed_args.config):
        if parsed_args.config == DEFAULT_CONFIGFILE:
            ConfigurationSettings().write_config(parsed_args.config)
            logger.error(f"Config file '{parsed_args.config}' did not exist! Please edit the newly-created config and re-run.")
            sys.exit(1)
        else:
            raise Exception(f"Config file '{parsed_args.config}' does not exist! Exiting")
    configuration_settings = ConfigurationSettings(parsed_args.config).get_config()

    start_time = time.time()
    profilepackage = load_config_package(configuration_settings, api_key, parsed_args.device_group,
                                         parsed_args.limit, no_api, parsed_args.xml)
    problems, total_problems = run_policy_validators(validators, profilepackage, output_fname)
    write_validator_output(problems, output_fname, 'text')
    end_time = time.time()

    logger.info(f"Full run took {end_time - start_time} seconds")
    logger.info(f"Detected a total of {total_problems} problems")

    return


if __name__ == '__main__':
    main()
