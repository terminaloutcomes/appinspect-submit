# appinspect-submit

A simple CLI for submitting your Splunk app package to AppInspect and reading the report.


# Installation

`pip install appinspect-submit`

# Usage

`$ appinspect-submit [OPTIONS] FILENAME`

Uploads your Splunk app package to the AppInspect service and downloads the report. Report filename will look like "%Y%m%d-%H%M%S-report.json

## Options:
    --test-future                   Use the 'future' tests
    --help                          Show this message and exit.
