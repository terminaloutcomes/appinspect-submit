#!/usr/bin/env python3

""" does the splunk appinspect thing

    based on the blog article here: https://www.splunk.com/en_us/blog/tips-and-tricks/managing-updates-to-the-splunk-cloud-vetting-process.html

"""

from datetime import datetime
from json import load as json_load
from json.decoder import JSONDecodeError
import os.path
import sys
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
CONFIG_FILENAME="~/.config/appinspect-submit.json"

REPORT_SUMMARY_KEYS = [
    'app_name',
    'app_description',
    'app_package_id',
    'app_version',
    'app_author',
    'app_hash',
]

class NotRequiredIf(click.Option):
    def __init__(self, *args, **kwargs):
        self.not_required_if = kwargs.pop('not_required_if')
        assert self.not_required_if, "'not_required_if' parameter required"
        kwargs['help'] = (kwargs.get('help', '') +
            ' NOTE: This argument is mutually exclusive with %s' %
            self.not_required_if
        ).strip()
        super(NotRequiredIf, self).__init__(*args, **kwargs)

    def handle_parse_result(self, ctx, opts, args):
        we_are_present = self.name in opts
        other_present = self.not_required_if in opts

        if other_present:
            if we_are_present:
                raise click.UsageError(
                    "Illegal usage: `%s` is mutually exclusive with `%s`" % (
                        self.name, self.not_required_if))
            else:
                self.prompt = None

        return super(NotRequiredIf, self).handle_parse_result(
            ctx, opts, args)

def print_underline(input_string: str, underline:str="-", max_length=120):
    """prints a line of <underline> as long as max_length or <len(input_string)>"""
    output_length = len(input_string)
    if output_length > max_length:
        output_length = max_length
    print(str(underline)*output_length)


@click.group()
def cli():
    """Uploads your Splunk app package to the AppInspect service and
    downloads the report. Report filename will look like "%Y%m%d-%H%M%S-report.json

    Configuration file: ~/.config/appinspect-submit.json can have username/password fields
    to automate submission.
    """


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
    "--username", type=str,
    # prompt="Splunk.com Username",
    help="Username on Splunk.com"
)
@click.option(
    "--test-future", is_flag=True, default=False, help="Use the 'future' tests"
)
@click.option(
    "--use-config",
    is_flag=True,
    help="Take username and password from ~/.config/appinspect-submit.json"
)
@click.password_option(
    "--password",
    prompt="Splunk.com Password",
    confirmation_prompt=False,
    help="Password for account on Splunk.com",
    cls=NotRequiredIf,
    not_required_if='use_config'
)
@cli.command()
def upload(username: str, filename: str, test_future: bool, log: str, **kwargs):
    """ upload the app for testing"""

    if kwargs.get("use_config"):
        print("Loading config", file=sys.stderr)
        if not os.path.exists(os.path.expanduser(CONFIG_FILENAME)):
            print(f"Failed to find config file: {CONFIG_FILENAME}", file=sys.stderr)
            sys.exit(1)
        with open(os.path.expanduser(CONFIG_FILENAME), 'r', encoding="utf8") as config_fh:
            try:
                config = json_load(config_fh)
            except JSONDecodeError as json_error:
                print(f"Error decoding config: {json_error}", file=sys.stderr)
                sys.exit(1)
            username=config.get("username")
            password=config.get("password")
            if not username and password:
                print("Ensure config file has username and password, quitting.", file=sys.stderr)
                sys.exit(1)

    elif kwargs.get("password"):
        password = kwargs.get("password")
    else:
        print("Either specify password in config or command line", file=sys.stderr)
        sys.exit(1)
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
@click.option("--ignore-result", "-I", multiple=True, help="Ignore a result (eg success) - specify can multiple times for different values.")
@click.option("--hide-empty-groups", is_flag=True, help="If all check groups are empty, don't show them")
@cli.command()
def report(filename: str, ignore_result: tuple, hide_empty_groups:bool):
    """{p}arse a report and do a simple output"""
    if not os.path.exists(filename):
        logger.error("Failed to find file {}, bailing", filename)
        return False

    if ignore_result:
        print(f"Ignoring the following result values: {', '.join(ignore_result)}")

    with open(filename, 'r', encoding="utf8") as file_handle:
        report_data = json_load(file_handle)

    if "summary" not in report_data:
        raise ValueError("Parsing fail - should include a summary key in data?")


    summary = report_data.get("summary")
    print("Report Summary")
    print_underline("Report Summary", underline="=")
    for key in summary:
        print(f"{COLOUR.get(key, COLOUR['default'])}{summary[key]}{COLOUR['end']}\t{key}")
    print("\n")

    if len(report_data.get('reports')) == 1:
        print(f"There is 1 report.\n")
    else:
        print(f"There are {len(report_data.get('reports'))} reports.\n")

    for report_index, report in enumerate(report_data.get("reports")):
        print(f"Report #:\t{COLOUR['white']}{report_index+1}{COLOUR['end']}")
        for key in REPORT_SUMMARY_KEYS:
            if report.get(key):
                print(f"{key}\t{COLOUR['white']}{report.get(key)}{COLOUR['end']}")

        print("")
        for group_index, group in enumerate(report.get("groups")):
            # check if all the items in this group have been skipped
            checks_without_skipped = [ check for check in group.get("checks") if check.get("result") not in ignore_result]

            if hide_empty_groups and len(checks_without_skipped) == 0:
                continue

            print(f"\n{COLOUR['warning']}Check Group #{group_index+1} - {group.get('description')}{COLOUR['end']}")
            print_underline(group.get("description"))

            if len(checks_without_skipped) == 0:
                print("All checks in this group have been ignored.")

            print("="*20)
            for check in checks_without_skipped:
                print("="*20)
                result = check.get("result")
                print(f"Result: {COLOUR.get(result, COLOUR.get('default'))}{result}{COLOUR.get('end')}")
                description = check.get('description').replace('\n', ' ')
                print(f"Check: {description}")
                # {result}")

                # print(check.keys())
                messages = check.get("messages")
                for message in messages:
                    print(message.get("message"))
                    if message.get("filename"):
                        print(f"Filename: {message.get('filename')}")

    print("Done!")

if __name__ == "__main__":
    cli()  # pylint: disable=no-value-for-parameter
