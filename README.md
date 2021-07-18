# appinspect-submit

A simple CLI for submitting your Splunk app package to AppInspect and getting the report.

Eventually I'll get around to making something to parse the reports - currently it'll just dump the raw JSON to the local directory.

# Installation

`pip install appinspect-submit`

# Usage

`appinspect-submit [OPTIONS] FILENAME`

Uploads your Splunk app package to the AppInspect service and downloads the report. Report filename will look like "%Y%m%d-%H%M%S-report.json

## Options:
    --username TEXT                 Username on Splunk.com
    --test-future                   Use the 'future' tests
    --password TEXT                 Password for account on Splunk.com
    --log [DEBUG|INFO|ERROR|WARNING]
    --help                          Show this message and exit.