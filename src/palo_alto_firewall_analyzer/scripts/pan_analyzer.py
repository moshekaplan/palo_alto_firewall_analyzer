#!/usr/bin/env python
import argparse
import datetime
import logging
import os.path
import sys
import time
import json

# Used to trigger loading the validators and fixers
import palo_alto_firewall_analyzer.validators
import palo_alto_firewall_analyzer.fixers

from palo_alto_firewall_analyzer.core import get_policy_validators, get_policy_fixers, ConfigurationSettings
from palo_alto_firewall_analyzer.pan_helpers import load_config_package, load_API_key

from palo_alto_firewall_analyzer.scripts.pan_details import get_json_detail

DEFAULT_CONFIG_DIR = os.path.expanduser("~" + os.sep + ".pan_policy_analyzer" + os.sep)
DEFAULT_CONFIGFILE = DEFAULT_CONFIG_DIR + "PAN_CONFIG.cfg"
DEFAULT_API_KEYFILE = DEFAULT_CONFIG_DIR + "API_KEY.txt"
EXECUTION_START_TIME = datetime.datetime.today().strftime('%Y%m%d_%H%M%S')
RUNTIME_START = time.time()
logger = logging.getLogger('palo_alto_firewall_analyzer')


###############################################################################
# General helper functions
###############################################################################
def configure_logging(enable_debug_log, console_enabled):
    logger.setLevel(logging.DEBUG)
    formatter = logging.Formatter('%(name)s - %(levelname)s - %(message)s')

    if enable_debug_log:
        logfile_path = f'pan_analyzer_debug_{EXECUTION_START_TIME}.log'
        fh = logging.FileHandler(logfile_path)
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(formatter)
        logger.addHandler(fh)

    if console_enabled:
        ch = logging.StreamHandler()
        ch.setLevel(logging.INFO)
        ch.setFormatter(formatter)
        logger.addHandler(ch)


def run_policy_fixers(fixers, profilepackage, output_fname):
    problems = {}
    total_problems = 0
    logger.info("Running fixers")

    for name, fixer_values in fixers.items():
        fixer_name, fixer_description, fixer_function = fixer_values
        fixer_problems = fixer_function(profilepackage)
        problems[(fixer_name, fixer_description)] = fixer_problems
        total_problems += len(fixer_problems)

    return problems, total_problems


def run_policy_validators(validators, profilepackage, output_fname):
    problems = {}
    total_problems = 0
    total_checks = 0
    logger.info("Running validators")

    for name, validator_values in validators.items():
        validator_name, validator_description, validator_function = validator_values
        validator_problems, count_checks = validator_function(profilepackage)
        problems[(validator_name, validator_description), count_checks] = validator_problems
        total_problems += len(validator_problems)
        total_checks += count_checks
    return problems, total_problems, total_checks


def write_analyzer_output_json(problems, fname, profilepackage, sum_total_checks):
    # build json
    total_problems = 0
    entries = []
    for validator_info, problem_entries in problems.items():
        validator_name, validator_description = validator_info[0]
        total_checks = validator_info[1]
        problems = []
        for problem_entry in problem_entries:
            if problem_entry.Detail is not None:
                problem = {"desc": problem_entry.text, "detail": get_json_detail(problem_entry.Detail)}
            else:
                problem = {"desc": problem_entry.text}
            problems.append(problem)
            total_problems += 1
        entry = {"validator_name": validator_name, "total_checks": total_checks, "problems": problems}
        entries.append(entry)
    end_time = time.time()
    data = {"config_version": profilepackage.pan_config.config_xml['version'],
            "detail-version": profilepackage.pan_config.config_xml['detail-version'],
            "urldb": profilepackage.pan_config.config_xml['urldb'],
            "date_execution": EXECUTION_START_TIME,
            "runtime": round(end_time - RUNTIME_START, 2),
            "total_problems": total_problems,
            "total_checks": sum_total_checks,
            "entries": entries
            }

    with open(fname, 'w') as fh:
        json.dump(data, fh)


def write_analyzer_output(problems, fname, profilepackage, sum_total_checks, out_format='text'):
    supported_output_formats = ["text", "json"]

    if out_format not in supported_output_formats:
        raise Exception(
            f"Unsupported output format of {out_format}! Output format must be one of {supported_output_formats}")

    if out_format == 'text':
        with open(fname, 'w') as fh:
            for validator_info, problem_entries in problems.items():
                validator_name, validator_description = validator_info

                fh.write("#" * 80 + '\n')
                fh.write(f"{validator_name}: {validator_description} ({len(problem_entries)}/{sum_total_checks})\n")
                fh.write("#" * 80 + '\n')
                for problem_entry in problem_entries:
                    # fh.write(f"Output for config name: {config_name} \n\n")
                    # if validator_problems:
                    fh.write(problem_entry.text + '\n')
                    # else:
                    #    fh.write('(none)\n')
                fh.write('\n')
    elif out_format == 'json':
        write_analyzer_output_json(problems, fname, profilepackage, sum_total_checks)


def build_output_fname(parsed_args):
    # Build the name of the output file
    if parsed_args.xml:
        xml_string = "_xml"
    else:
        xml_string = ''
    if parsed_args.device_group:
        devicegroup_string = "_" + parsed_args.device_group
    else:
        devicegroup_string = ''

    if parsed_args.fixer:
        fixers_string = "_" + parsed_args.fixer
    else:
        fixers_string = ''

    if parsed_args.validator:
        validators_string = "_" + "_".join(sorted(parsed_args.validator))
    else:
        validators_string = ''

    if parsed_args.limit:
        limit_string = "_limit" + str(parsed_args.limit)
    else:
        limit_string = ""

    if parsed_args.output_format == 'json':
        extension = '.json'
    else:
        extension = '.txt'

    output_fname = f'pan_analyzer_output_{EXECUTION_START_TIME}{devicegroup_string}{xml_string}{validators_string}{fixers_string}{limit_string}{extension}'

    return output_fname


def main():
    description = "Checks or fixes Palo Alto Firewall issues."
    validator_listing = '\n'.join(f" * {readable_name} - {description}" for readable_name, description, f in
                                  sorted(get_policy_validators().values()))
    validator_epilog = f"""Here is a detailed list of the {len(get_policy_validators().keys())} supported validators:\n{validator_listing}\n"""

    fixer_listing = '\n'.join(f" * {readable_name} - {description}" for readable_name, description, f in
                              sorted(get_policy_fixers().values()))
    fixer_epilog = f"""Here is a detailed list of the {len(get_policy_fixers().keys())} supported fixers:\n{fixer_listing}\n"""

    epilog = validator_epilog + "\n\n" + fixer_epilog
    parser = argparse.ArgumentParser(description=description, epilog=epilog,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    # TODO: Make this a positional argument, where only one can be selected, and influences which of the remaining arguments are available.
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--validator", help="Only run specified validators (repeat for multiple)",
                       choices=sorted(get_policy_validators().keys()), action='append')
    group.add_argument("--fixer", help="Fixer to run", choices=sorted(get_policy_fixers().keys()))

    parser.add_argument("--device-group", help="Device Group to run through validator (defaults to all)")
    parser.add_argument("--quiet", help="Silence output", action='store_true')
    parser.add_argument("--config", help=f"Config file to read (default is {DEFAULT_CONFIGFILE})", default=DEFAULT_CONFIGFILE)
    parser.add_argument("--api", help=f"File with API Key (default is {DEFAULT_API_KEYFILE})", default=DEFAULT_API_KEYFILE)

    # These next group of options are only for validators, not fixers:
    parser.add_argument("--xml", help="Process an XML file from 'Export Panorama configuration version'. This skips validators that require an API key")

    parser.add_argument("--debug", help="Write all debug output to pan_validator_debug_YYMMDD_HHMMSS.log", action='store_true')
    parser.add_argument("--limit", help="Limit processing to the first N rules (useful for debugging)", type=int)
    parser.add_argument("--output-format", help="Type File Output, default='text'", default="text", type=str, choices=['text', 'json'])

    parsed_args = parser.parse_args()

    configure_logging(parsed_args.debug, not parsed_args.quiet)
    logger.debug(f"Script launched with the following arguments {' '.join(sys.argv)}")
    logger.debug(f"Execution began at {EXECUTION_START_TIME}")

    output_fname = build_output_fname(parsed_args)
    logger.debug(f"Writing output to {output_fname}")

    if parsed_args.xml:
        api_key = ''
    else:
        api_key = load_API_key(parsed_args.api)

    if not os.path.isfile(parsed_args.config):
        if parsed_args.config == DEFAULT_CONFIGFILE:
            ConfigurationSettings().write_config(parsed_args.config)
            logger.error(f"Config file '{parsed_args.config}' did not exist! Please edit the newly-created config and re-run.")
            return 1
        else:
            raise Exception(f"Config file '{parsed_args.config}' does not exist! Exiting")
    configuration_settings = ConfigurationSettings(parsed_args.config).get_config()

    if parsed_args.fixer and parsed_args.xml:
        logger.error("Cannot run fixers against an XML file! --fixer and --xml are mutually exclusive")
        return 1

    start_time = time.time()
    profilepackage = load_config_package(configuration_settings, api_key, parsed_args.device_group,
                                         parsed_args.limit, parsed_args.xml)

    if parsed_args.fixer:
        fixers = {parsed_args.fixer: get_policy_fixers()[parsed_args.fixer]}
        problems, total_problems = run_policy_fixers(fixers, profilepackage, output_fname)
    else:
        if parsed_args.validator:
            validators = {validator: get_policy_validators()[validator] for validator in parsed_args.validator}
        else:
            validators = get_policy_validators()

        problems, total_problems, total_checks = run_policy_validators(validators, profilepackage, output_fname)

    write_analyzer_output(problems, output_fname, profilepackage, total_checks, parsed_args.output_format)

    end_time = time.time()

    logger.info(f"Full run took {round(end_time - start_time, 2)} seconds")
    logger.info(f"Detected a total of {total_problems} problems")

    return 0


if __name__ == '__main__':
    sys.exit(main())
