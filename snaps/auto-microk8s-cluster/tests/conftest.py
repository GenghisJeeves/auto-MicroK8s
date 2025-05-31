import os
import sys
from unittest.mock import patch

import pytest

# Add the src directory to the path so we can import the module
sys.path.insert(
    0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src"))
)


# Apply patches before any tests are run
@pytest.fixture(scope="session", autouse=True)
def patch_arg_parser():
    """
    Patch argparse.ArgumentParser.parse_args to prevent it from
    trying to parse pytest's command line arguments
    """
    with patch("argparse.ArgumentParser.parse_args") as mock_parse_args:
        # Configure the mock to return an object with the attributes we need
        mock_parse_args.return_value.loglevel = "info"
        mock_parse_args.return_value.port = 8800
        mock_parse_args.return_value.discovery_port = 8801
        yield
