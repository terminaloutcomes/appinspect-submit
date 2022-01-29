#!/usr/bin/env python

""" does the splunk appinspect thing

    based on the blog article here: https://www.splunk.com/en_us/blog/tips-and-tricks/managing-updates-to-the-splunk-cloud-vetting-process.html

"""

import json
from json.decoder import JSONDecodeError
import os.path
from pathlib import Path
import sys

import click
from loguru import logger

from . import AppInspectCLI

logger.configure()

# https://gist.github.com/rene-d/9e584a7dd2935d0f461904b9f2950007
COLOUR = {
    "success": "\033[92m",
    "failure": "\033[91m",
    "error": "\033[91m",
    "skipped": "\033[95m",
    "manual_check": "\033[93m",
    "warning": "\033[93m",
    "not_applicable": "\033[95m",
    "default": "\033[95m",
    "end": "\033[0m",
    "white": "\033[1;37m",
}
CONFIG_FILENAME = "~/.config/appinspect-submit.json"


REPORT_SUMMARY_KEYS = [
    "app_name",
    "app_description",
    "app_package_id",
    "app_version",
    "app_author",
    "app_hash",
]


class NotRequiredIf(click.Option):
    """Does multi-value checks"""

    def __init__(self, *args, **kwargs):
        self.not_required_if = kwargs.pop("not_required_if")
        assert self.not_required_if, "'not_required_if' parameter required"
        kwargs["help"] = (
            kwargs.get("help", "")
            + f" NOTE: This argument is mutually exclusive with {self.not_required_if}"
        ).strip()
        super().__init__(*args, **kwargs)

    def handle_parse_result(self, ctx, opts, args):
        we_are_present = self.name in opts
        other_present = self.not_required_if in opts

        if other_present:
            if we_are_present:
                raise click.UsageError(
                    f"Illegal usage: `{self.name}` is mutually exclusive with `{self.not_required_if}`"
                )
            self.prompt = None

        return super().handle_parse_result(ctx, opts, args)


def colourprint(text: str, colour_name: str, end: str = "\n"):
    """prints text with the required colour"""
    if colour_name not in COLOUR:
        print(f"Color {colour_name} not in {','.join(COLOUR)}", file=sys.stderr)
    colour_value = COLOUR.get(colour_name, "default")
    output = f"{colour_value}{text}{COLOUR['end']}"
    print(output, end=end)


def print_underline(input_string: str, underline: str = "-", max_length=120):
    """prints a line of <underline> as long as max_length or <len(input_string)>"""
    output_length = min(max_length, len(input_string))
    print(str(underline) * output_length)

def set_log_level(level: str):
    """sets the log level"""
    if level not in ["INFO", "DEBUG"]:
        print(f"Log level {level} invalid, bailing.")
        sys.exit(1)
    logger.remove()
    logger.add(sys.stderr, level=level)

@click.group()
def cli():
    """Uploads your Splunk app package to the AppInspect service and
    downloads the report. Report filename will look like "%Y%m%d-%H%M%S-report.json

    Configuration file: ~/.config/appinspect-submit.json needs to have username/password fields
    to automate submission.
    """

@click.argument(
    "filename",
    type=click.Path(
        exists=True, dir_okay=False, readable=True, resolve_path=True, allow_dash=False
    ),
)
@click.option(
    "--test-future", is_flag=True, default=False, help="Use the 'future' tests"
)
@click.option(
    "--debug", is_flag=True, default=False, help="Set the logging level to DEBUG"
)
@cli.command()
def upload(filename: str, test_future: bool, debug: bool):
    """upload the app for testing"""

    set_log_level("DEBUG" if debug else "INFO")

    print("Loading config", file=sys.stderr)
    configfile = Path(os.path.expanduser(CONFIG_FILENAME))
    if not configfile.exists():
        print(f"Failed to find config file: {configfile.as_posix()}", file=sys.stderr)
        sys.exit(1)
    try:
        config = json.load(configfile.open(encoding="utf-8"))
    except JSONDecodeError as json_error:
        print(f"Error decoding config: {json_error}", file=sys.stderr)
        sys.exit(1)
    if not "username" in config and "password" in config:
        print(
            "Ensure config file has username and password, quitting.", file=sys.stderr
        )
        sys.exit(1)
    username = config["username"]
    password = config["password"]

    if not os.path.exists(filename):
        logger.error("Failed to find file {}, bailing", filename)
        return False

    appinspect = AppInspectCLI(username, password, filename, test_future)

    appinspect.do_login()
    appinspect.do_submission()

    logger.info("Waiting for the report to finish...")
    appinspect.do_wait_for_status()
    logger.info("Grabbing the report...")

    appinspect.do_pull_report()
    logger.info("Done, wrote report  to {}", appinspect.report_filename)

    logger.info("Complete! Report filename: {}", appinspect.report_filename)
    return True


def print_num_reports(report_count: int) -> None:
    """prettyprint numbers"""
    if report_count == 1:
        print("There is 1 report.\n")
    else:
        print(f"There are {report_count} reports.\n")


@click.argument("filename", type=click.File())
@click.option(
    "--ignore-result",
    "-I",
    multiple=True,
    help="Ignore a result (eg success) - specify can multiple times for different values.",
)
@click.option(
    "--hide-empty-groups",
    "-e",
    is_flag=True,
    help="If all check groups are empty, don't show them",
)
@click.option(
    "--debug", is_flag=True, default=False, help="Set the logging level to DEBUG"
)
@cli.command()
def report(
    filename,
    ignore_result: tuple,
    hide_empty_groups: bool,
    debug: bool,
    ):
    """Parse a report and do a simple output"""

    set_log_level("DEBUG" if debug else "INFO")
    if ignore_result:
        print(f"Ignoring the following result values: {', '.join(ignore_result)}")

    report_data = json.load(filename)

    if "summary" not in report_data:
        raise ValueError("Parsing fail - should include a summary key in data?")

    print("Report Summary")
    print_underline("Report Summary", underline="=")
    for key in report_data["summary"]:
        colourprint(report_data["summary"][key], "default", end="")
        print(f"\t{key}")
    print("\n")

    print_num_reports(len(report_data.get("reports")))

    for report_index, element in enumerate(report_data.get("reports")):
        colourprint(f"Report #:\t{report_index+1}", "white")
        for key in [ key for key in REPORT_SUMMARY_KEYS if element.get(key)]:
            colourprint(f"{key}\t{element.get(key)}", "white")

        print("")
        for group_index, group in enumerate(element.get("groups")):
            # check if all the items in this group have been skipped
            checks_without_skipped = [
                check
                for check in group.get("checks")
                if check.get("result") not in ignore_result
            ]

            if hide_empty_groups and len(checks_without_skipped) == 0:
                continue

            colourprint(
                f"\nCheck Group #{group_index+1} - {group.get('description')}",
                "warning",
            )
            print_underline(group.get("description"))

            if len(checks_without_skipped) == 0:
                print("All checks in this group have been ignored.")

            print("=" * 20)
            for check in checks_without_skipped:
                print("=" * 20)
                result = check.get("result")
                colourprint(f"Result: {result}", result)
                description = check.get("description").replace("\n", " ")
                print(f"Check: {description}")
                # {result}")

                # print(check.keys())
                if not "messages" in check:
                    continue
                for message in check["messages"]:
                    print(message.get("message"))
                    if message.get("filename"):
                        print(f"Filename: {message['filename']}")

    print("Done!")


if __name__ == "__main__":
    cli()  # pylint: disable=no-value-for-parameter
