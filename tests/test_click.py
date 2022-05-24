""" testing click functionality """

from click.testing import CliRunner
from appinspect_submit.__main__ import cli

def test_command_help() -> None:
    """ test that something works using click """
    runner = CliRunner()
    result = runner.invoke(
        cli,
        [
            "--help",
        ],
        )
    assert result.exit_code == 0
    print(result)

def test_command_report() -> None:
    """ test that something works using click """
    runner = CliRunner()
    result = runner.invoke(
        cli,
        [
            "report",
            "test_report.json",
        ],
        )
    assert result.exit_code == 0
    print(result)
    assert 'Report Summary' in result.stdout
