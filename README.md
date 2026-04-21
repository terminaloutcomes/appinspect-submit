# appinspect-submit

A simple CLI for submitting your Splunk app package to AppInspect and reading the report.

## Installation

To install the published CLI with `uv`:

`uv tool install appinspect-submit`

To work on this repository locally:

`uv sync --dev`

Then run the CLI or tests with:

- `uv run appinspect-submit --help`
- `uv run pytest`

## Usage

`uv run appinspect-submit [OPTIONS] FILENAME`

Uploads your Splunk app package to the AppInspect service and downloads the report. Report filename will look like "%Y%m%d-%H%M%S-report.json

### Options

    --test-future                   Use the 'future' tests
    --help                          Show this message and exit.

### Configuration

You can set APPINSPECT_USERNAME and APPINSPECT_PASSWORD for auth instead of having a config file.
