import os
from typing import Literal

from pydantic import ValidationError
from pydantic_settings import (
    BaseSettings,
    PydanticBaseSettingsSource,
    SettingsConfigDict,
    TomlConfigSettingsSource,
)


class Settings(BaseSettings):
    """Configuration for the auto-microk8s-cluster snap."""

    # Define the configuration fields with their types and constraints
    log_level: Literal["INFO", "DEBUG", "WARNING", "ERROR"] = (
        "WARNING"  # Log level (e.g., "info", "debug", "error")
    )
    config_file: str = "config.toml"  # Path to the configuration file
    if os.environ.get("SNAP_DATA") is not None:
        # We are runnng in a snap so use the snap data directory
        config_file = os.path.join(os.environ["SNAP_DATA"], config_file)
    model_config = SettingsConfigDict(toml_file=config_file)

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        return (TomlConfigSettingsSource(settings_cls),)


def main():
    # Get the settings from snapcraft if available

    log_level = os.system("snapctl get log-level")
    # Need to validate if this is valid, otherwise use default
    log_level = "INFO"
    try:
        Settings(log_level=log_level)
    except ValidationError as e:
        print(f"Invalid log level: {log_level}. Using default: {Settings().log_level}")

    print("Settings file log level: ", Settings().log_level)
    print("Snapctl log level: ", log_level)
    if log_level != Settings().log_level:
        print(f"Log level mismatch: {log_level} != {Settings().log_level}")
        # Set the Settings file log level to the snapctl log level and restart the service
        Settings().log_level = log_level
        Settings().model_dump()
        print("Log level updated in settings file.")
    else:
        print("Log level matches settings file, nothing to do")


if __name__ == "__main__":
    main()
