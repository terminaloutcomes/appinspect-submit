""" does the splunk appinspect thing

    based on the blog article here: https://www.splunk.com/en_us/blog/tips-and-tricks/managing-updates-to-the-splunk-cloud-vetting-process.html

"""

from datetime import datetime
import json

import time
from typing import Any, Dict, List, Optional

import requests
import requests.exceptions

from loguru import logger

from appinspect_submit.config import Config
from appinspect_submit.constants import APPINSPECT_BASE_URL, LOGINURL, LOOP_WAIT_TIME


class AppInspectCLI:  # pylint: disable=too-many-instance-attributes
    """Does AppInspect Things"""

    def __init__(
        self,
        filename: str,
        username: Optional[str] = None,
        password: Optional[str] = None,
        tags: List[str] = [],
    ) -> None:
        """does the startup thing"""
        self.config = Config()
        if username is not None:
            self.config.username = username

        if password is not None:
            self.config.password = password

        if self.config.username is None:
            logger.error("No username provided, bailing")
            raise ValueError("No username provided")

        if self.config.password is None:
            logger.error("No password provided, bailing")
            raise ValueError("No password provided")

        self.filename = filename
        self.token = ""
        self.request_id = ""
        self.urls: dict[str, Any] = {}
        self.report_filename = ""
        self.tags = tags

    def __str__(self) -> str:
        """string repr"""
        return f'AppInspectCLI(filename="{self.filename}", username="{self.config.username}")'

    def do_login(self) -> bool:
        """does the login thing"""
        logger.info("Trying to log in...")
        if self.config.username is None or self.config.password is None:
            logger.error("No username or password, bailing")
            return False
        responsedata = self.do_get_json(
            LOGINURL, auth=(self.config.username, self.config.password)
        )
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

    def get_auth_header(self) -> dict[str, str]:
        """returns the bearer header"""
        return {"Authorization": f"Bearer {self.token}"}

    def do_get_json(
        self,
        url: str,
        auth: Optional[
            tuple[
                str,
                str,
            ]
        ] = None,
        headers: dict[str, str] = {},
    ) -> dict[str, Any]:
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
            responsedata: dict[str, Any] = response.json()
            logger.trace(response.json())
        except json.JSONDecodeError as error_message:
            logger.error(
                "Failed to decode response into JSON: error={} content={}",
                error_message,
                response.content,
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
            tags = ["cloud"]
            tags.extend(self.tags)
            logger.info("Tags: {}", tags)
            files: Dict[str, Any] = {
                "app_package": upload_file_handle,
            }
            if tags:
                files["included_tags"] = (None, ",".join(tags))

            try:
                logger.debug("Uploading file...")
                response = requests.post(
                    url=f"{APPINSPECT_BASE_URL}/v1/app/validate",
                    headers=headers,
                    files=files,
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

        jsondata = response.json()
        logger.debug("Validate upload response: {}", jsondata)
        if "warning" in jsondata:
            logger.warning("Warning: {}", jsondata.get("warning"))
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
                # logger.info(
                #     "Response status changed from PROCESSING, is now {} finishing...",
                #     responsedata.get("status"),
                # )
                logger.debug(json.dumps(responsedata))
                if responsedata.get("status") == "SUCCESS":
                    logger.info("Report finished successfully!")
                    return True
                else:
                    logger.error(
                        "Report finished with non-success value: {}",
                        responsedata.get("status"),
                    )
                    return False

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
