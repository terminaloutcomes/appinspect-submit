""" does the splunk appinspect thing

    based on the blog article here: https://www.splunk.com/en_us/blog/tips-and-tricks/managing-updates-to-the-splunk-cloud-vetting-process.html

"""
from datetime import datetime
from collections import namedtuple
import json

import sys
import time
import requests
import requests.exceptions

from loguru import logger
from click import progressbar

LOGINURL = "https://api.splunk.com/2.0/rest/login/splunk"
APPINSPECT_BASE_URL = "https://appinspect.splunk.com"

LOOP_WAIT_TIME = 5


def showfunc(item):
    """because lambdas are hard"""
    if item:
        return item.name
    return ""


class AppInspectCLI:  # pylint: disable=too-many-instance-attributes
    """Does AppInspect Things"""

    def __init__(
        self, username: str, password: str, filename: str, test_future: bool
    ) -> None:
        """does the startup thing"""
        self.username = username
        self.password = password
        self.filename = filename
        self.test_future = test_future
        self.token = ""
        self.request_id = ""
        self.urls: dict = {}
        self.report_filename = ""

    def do_login(self) -> bool:
        """does the login thing"""
        logger.info("Trying to log in...")
        responsedata = self.do_get_json(LOGINURL, auth=(self.username, self.password))
        if not responsedata:
            logger.error("Failed to login, bailing")
            return False

        if responsedata.get("status") != "success":
            logger.error("Failed to login, bailing: {}", json.dumps(responsedata))
            return False

        self.token = responsedata.get("data", {}).get("token")
        if not self.token:
            logger.error("Failed to get token from this: {}", json.dumps(responsedata))
            return False

        logger.debug("Successfully grabbed token: {}", self.token)

        if responsedata.get("data", {}).get("user", {}).get("name"):
            logger.info(
                "Logged in successfully as {}.",
                responsedata.get("data", {}).get("user", {}).get("name"),
            )
            return True

        logger.info("Logged in successfully.")
        return True

    get_auth_header = lambda self: {"Authorization": f"Bearer {self.token}"}

    def do_get_json(self, url: str, headers: dict = None, auth: tuple = ()) -> dict:
        """does a standard get request and returns a dict from the JSON"""
        if not headers:
            headers = self.get_auth_header()
        try:
            response = requests.get(url=url, headers=headers, auth=auth)
            response.raise_for_status()

        except requests.exceptions.HTTPError as error_message:
            logger.error("Failed to GET url={}, error={}", url, error_message)
            logger.error("Response headers: {}", response.headers)
            logger.error("Response content: {}", response.content)
        try:
            responsedata = response.json()
            logger.debug(response.json())
        except json.JSONDecodeError as error_message:
            logger.error(
                "Failed to decode response into JSON: error={} content={}",
                error_message,
                responsedata.content,
            )
            return {}
        return responsedata

    def do_submission(self) -> bool:
        """does the appinspect upload part"""
        logger.info("Uploading file...")

        #     curl -X POST -H "Authorization: bearer auth_token_here" \
        # -F  "app_package=@app_name_here.tar.gz" \
        # -F  "included_tags=future" \
        # --url "https://appinspect.splunk.com/v1/app/validate"
        if not self.token.strip():
            logger.error("Blank token... this is going to fail!")
            return False

        headers = self.get_auth_header()

        with open(self.filename, "rb") as upload_file_handle:
            files = {"app_package": upload_file_handle}
            data = {}
            data["included_tags"] = ["cloud"]
            if self.test_future:
                data["included_tags"].append("future")

            try:
                logger.debug("Uploading file...")
                response = requests.post(
                    url=f"{APPINSPECT_BASE_URL}/v1/app/validate",
                    headers=headers,
                    files=files,
                    data=data,
                )
                logger.debug("Done, let's see if it failed...")
                response.raise_for_status()
            except requests.exceptions.HTTPError as error_message:
                logger.error(error_message)
                logger.error("Response headers: {}", response.headers)
                logger.error("Response content: {}", response.content)
                return False

        # An example response:
        # {"request_id": "ed14950a-3b9f-45aa-b1c1-8f60acdb4c1b",
        # "message": "Validation request submitted.",
        # "links": [{"href": "/v1/app/validate/status/ed14950a-3b9f-45aa-b1c1-8f60acdb4c1b",
        #            "rel": "status"},
        #           {"href": "/v1/app/report/ed14950a-3b9f-45aa-b1c1-8f60acdb4c1b",
        #            "rel": "report"}]}
        # we need to poll the status thing until it's done, then pull the report

        try:
            responsedata = response.json()
        except json.JSONDecodeError as error_message:
            logger.error(
                "Failed to parse response as JSON, something's broken: {} Content on next line:\n{}",
                error_message,
                response.content,
            )
            return False
        self.request_id = responsedata.get("request_id")
        if not self.request_id:
            logger.error(
                "Failed to find request_id in response: {}",
                json.dumps(response.json),
            )
            return False

        for link in responsedata.get("links"):
            self.urls[link.get("rel")] = link.get("href")

        failed = False
        missing_urls = []
        for expected_link in ("report", "status"):
            if expected_link not in self.urls:
                missing_urls.append(expected_link)
                failed = True
        if failed:
            logger.error(
                "Failed to find the following links in the validate response: {}",
                ", ".join(missing_urls),
            )
            return False

        logger.debug("Validate upload response: {}", response.json())
        return True

    def do_wait_for_status(
        self,
    ) -> bool:
        """waits for the thing to finish..."""

        start_time = time.time()
        while True:
            # because who doesn't love an infinite loop?
            time.sleep(LOOP_WAIT_TIME)
            status_url = f"{APPINSPECT_BASE_URL}{self.urls.get('status')}"

            runtime = round(time.time() - start_time, 1)
            logger.debug(
                "Still waiting for the report to finish... has been {} seconds", runtime
            )

            responsedata = self.do_get_json(status_url)
            if not responsedata:
                return False

            if responsedata.get("status") != "PROCESSING":
                logger.info(
                    "Response status changed from PROCESSING, is now {} finishing...",
                    responsedata.get("status"),
                )
                logger.debug(json.dumps(responsedata))
                return True

    def do_pull_report(
        self,
    ) -> bool:
        """waits for the thing to finish..."""
        report_url = f"{APPINSPECT_BASE_URL}{self.urls.get('report')}"
        report = self.do_get_json(report_url)
        if not report:
            return False
        self.report_filename = datetime.now().strftime("%Y%m%d-%H%M%S-report.json")
        with open(self.report_filename, "w", encoding="utf8") as report_filehandle:
            json.dump(report, report_filehandle, indent=4)
        return True
