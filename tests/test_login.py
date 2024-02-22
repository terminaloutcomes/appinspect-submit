import logging
from typing import Any, Dict, Tuple

import pytest

from appinspect_submit.config import Config
from appinspect_submit import AppInspectCLI

from . import TEST_USERNAME, testconfig  # noqa: F401

logging.basicConfig(level=logging.DEBUG)


@pytest.mark.network
def test_live_login() -> None:
    """tests actually logging in, you need a valid config / env var"""
    config = Config()
    if not config.username or not config.password:
        pytest.skip("No username/password found, skipping")

    appinspect = AppInspectCLI(
        "", username=config.username, password=config.password, tags=[]
    )

    assert appinspect.do_login()


def mocked_login(url: str, auth: Tuple[str, str]) -> Dict[str, Any]:
    """mocked login response"""
    return {
        "data": {
            "groups": [],
            "token": "superlongtokenthing",
            "user": {
                "email": "foo@example.com",
                "name": "Test User",
                "username": TEST_USERNAME,
            },
        },
        "msg": "Successfully authenticated user and assigned a token",
        "status": "success",
        "status_code": 200,
    }


def test_mocked_login(
    testconfig: Config,  # noqa: F811
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """tests mocked login"""

    appinspect = AppInspectCLI(
        "", username=testconfig.username, password=testconfig.password, tags=[]
    )
    with monkeypatch.context() as monkey:
        # patch out the request to the backend
        monkey.setattr(appinspect, "do_get_json", mocked_login)
        assert appinspect.do_login()
        assert appinspect.token == "superlongtokenthing"
