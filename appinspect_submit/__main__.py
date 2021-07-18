#!/usr/bin/env python3

""" does the splunk appinspect thing

    based on the blog article here: https://www.splunk.com/en_us/blog/tips-and-tricks/managing-updates-to-the-splunk-cloud-vetting-process.html

"""

from datetime import datetime
import os.path
from uuid import uuid4

import click
from loguru import logger

from . import AppInspectCLI

@click.command()
@click.argument(
    "filename",
    type=click.Path(
        exists=True, dir_okay=False, readable=True, resolve_path=True, allow_dash=False
    ),
)
@click.option("--username", type=str, prompt="Splunk.com Username", help="Username on Splunk.com")
@click.option(
    "--test-future", is_flag=True, default=False, help="Use the 'future' tests"
)
@click.password_option(
    "--password", prompt="Splunk.com Password", confirmation_prompt=False,
    help="Password for account on Splunk.com",
)
@click.option(
    "--log", default="INFO", type=click.Choice(["DEBUG", "INFO", "ERROR", "WARNING"],
    # help="Set the log level in the log file",
    )
)
def cli(username: str, password: str, filename: str, test_future: bool, log: str):
    """ Uploads your Splunk app package to the AppInspect service and
downloads the report. Report filename will look like "%Y%m%d-%H%M%S-report.json """
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


if __name__ == "__main__":
    cli()  # pylint: disable=no-value-for-parameter
