import json
import logging

from pathlib import Path
from typing import Any, Dict, Optional, Tuple

from pydantic.fields import FieldInfo
from pydantic_settings import (
    BaseSettings,
    PydanticBaseSettingsSource,
    SettingsConfigDict,
)

from appinspect_submit.constants import CONFIG_FILENAME


class JsonConfigSettingsSource(PydanticBaseSettingsSource):
    """
    A simple settings source class that loads variables from a JSON file
    at the project's root.
    """

    def get_field_value(
        self, field: FieldInfo, field_name: str
    ) -> Tuple[Any, str, bool]:
        try:
            file_content_json = json.load(Path(CONFIG_FILENAME).open(encoding="utf-8"))
            field_value = file_content_json.get(field_name)
            return field_value, field_name, False
        except Exception as error:
            logging.error("Failed to load config file %s: %s", CONFIG_FILENAME, error)
        return (None, "", False)

    def prepare_field_value(
        self, field_name: str, field: FieldInfo, value: Any, value_is_complex: bool
    ) -> Any:
        return value

    def __call__(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {}

        for field_name, field in self.settings_cls.model_fields.items():
            field_value, field_key, value_is_complex = self.get_field_value(
                field, field_name
            )
            field_value = self.prepare_field_value(
                field_name, field, field_value, value_is_complex
            )
            if field_value is not None:
                d[field_key] = field_value

        return d


class Config(BaseSettings):
    username: Optional[str] = None
    password: Optional[str] = None

    model_config = SettingsConfigDict(env_prefix="APPINSPECT_")
