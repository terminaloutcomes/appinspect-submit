import pytest

from appinspect_submit.config import Config

TEST_USERNAME = "sdfsdafsdfasdfasdf"
TEST_PASSWORD = "adlfjkashdflkasjhflksjadfh"


@pytest.fixture()
def testconfig() -> Config:
    config = Config()
    config.username = TEST_USERNAME
    config.password = TEST_PASSWORD
    return config
