#!/usr/bin/env python3

""" does the splunk appinspect thing

    based on the blog article here: https://www.splunk.com/en_us/blog/tips-and-tricks/managing-updates-to-the-splunk-cloud-vetting-process.html

"""

from json import load as json_load
from datetime import datetime
import os.path
from uuid import uuid4

import click
from loguru import logger

from . import AppInspectCLI

# https://gist.github.com/rene-d/9e584a7dd2935d0f461904b9f2950007
COLOUR = {
    "success" : '\033[92m',
    "failure" : '\033[91m',
    "error" : '\033[91m',
    "skipped" : '\033[95m',
    "manual_check" : '\033[93m',
    "warning" : '\033[93m',
    "not_applicable" : '\033[95m',
    "default" : '\033[95m',
    "end" : '\033[0m',
    "white" : '\033[1;37m',
}
@click.group()
def cli():
    """Uploads your Splunk app package to the AppInspect service and
    downloads the report. Report filename will look like "%Y%m%d-%H%M%S-report.json"""


@click.argument(
    "filename",
    type=click.Path(
        exists=True, dir_okay=False, readable=True, resolve_path=True, allow_dash=False
    ),
)

@click.option(
    "--log",
    default="INFO",
    type=click.Choice(
        ["DEBUG", "INFO", "ERROR", "WARNING"],
        # help="Set the log level in the log file",
    ),
)
@click.option(
    "--username", type=str, prompt="Splunk.com Username", help="Username on Splunk.com"
)
@click.option(
    "--test-future", is_flag=True, default=False, help="Use the 'future' tests"
)
@click.password_option(
    "--password",
    prompt="Splunk.com Password",
    confirmation_prompt=False,
    help="Password for account on Splunk.com",
)
@cli.command()
def upload(username: str, password: str, filename: str, test_future: bool, log: str):
    """ upload the app for testing"""
    if not os.path.exists(filename):
        logger.error("Failed to find file {}, bailing", filename)
        return False
    # remove the existing logger and update it
    session = uuid4()
    logfile_name = datetime.now().strftime("%Y%m%d-%H%M%S-appinspect.log")
    with open(logfile_name, "w") as logfile_handle:
        logger.info("Logging to file: {}", logfile_name)
        logger.remove()
        logger.add(
            sink=logfile_handle,
            level=log,
            format="<green>{time:YYYY-MM-DD HH:mm:ss}</green> session="
            + str(session)
            + ' level=<level>{level}</level> func=<cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> message="<level>{message}</level>"',
        )

        AppInspectCLI(username, password, filename, test_future)
    return True

@click.argument(
    "filename",
    type=click.Path(
        exists=True, dir_okay=False, readable=True, resolve_path=True, allow_dash=False
    ),
)
@cli.command()
def report(filename: str):
    """parse a report and do a simple output"""
    if not os.path.exists(filename):
        logger.error("Failed to find file {}, bailing", filename)
        return False

    with open(filename, 'r', encoding="utf8") as file_handle:
        report_data = json_load(file_handle)

    if "summary" not in report_data:
        raise ValueError("Parsing fail - should include a summary key in data?")



    summary = report_data.get("summary")
    print("Summary:\n========")
    for key in summary:
        print(f"{COLOUR.get(key, COLOUR['default'])}{summary[key]}{COLOUR['end']}\t{key}")
    print("\n")
    # print(report_data.keys())
    if len(report_data.get('reports')) == 1:
        print(f"There is 1 report.\n")
    else:
        print(f"There are {len(report_data.get('reports'))} reports.\n")

    for report_index, report in enumerate(report_data.get("reports")):

        print(f"Report #:\t{COLOUR['white']}{report_index+1}{COLOUR['end']}")
        for key in ['app_author', 'app_description', 'app_hash', 'app_name', 'app_package_id', 'app_version']:
            if report.get(key):
                print(f"{key}\t{COLOUR['white']}{report.get(key)}{COLOUR['end']}")

        groups = report.get("groups")

        print("")
        for group_index, group in enumerate(groups):
            print(f"\n{COLOUR['warning']}Check Group #{group_index+1} - {group.get('description')}{COLOUR['end']}")
            print("-"*len(group.get("description")))
            for check in group.get("checks"):
                result = check.get("result")
                print(f"Result: {COLOUR.get(result, COLOUR.get('default'))}{result}{COLOUR.get('end')}")
                description = check.get('description').replace('\n', ' ')
                print(f"Check: {description}")
                # {result}")
                print("="*20)

                # print(check.keys())
                messages = check.get("messages")
                for message in messages:
                    print(message.get("message"))
                    if message.get("filename"):
                        print(f"Filename: {message.get('filename')}")

    print("Done!")

if __name__ == "__main__":
    cli()  # pylint: disable=no-value-for-parameter
