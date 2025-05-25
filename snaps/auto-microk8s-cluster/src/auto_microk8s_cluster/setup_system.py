import logging
import subprocess
import time
from typing import Any

import requests_unixsocket
from dasbus.connection import SystemMessageBus
from dasbus.typing import UInt16, UInt32

# Configure logging
logger = logging.getLogger(__name__)


# Function to interact with snapd API using requests-unixsocket
def connect_to_snapd(
    method: str, endpoint: str, data: dict[str, Any] | None = None
) -> dict[str, Any]:
    """
    Connect to the snapd API via the UNIX socket using requests-unixsocket.

    Args:
        method: HTTP method (GET, POST)
        endpoint: API endpoint (e.g., /v2/snaps/microk8s)
        data: Optional data for POST requests

    Returns:
        The JSON response from the API
    """
    # Create a requests-unixsocket session
    session = requests_unixsocket.Session()

    # Format the URL for Unix socket
    url = f"http+unix://%2Frun%2Fsnapd.socket{endpoint}"

    try:
        if method.upper() == "GET":
            response = session.get(url)
        elif method.upper() == "POST":
            response = session.post(url, json=data)
        else:
            raise ValueError(f"Unsupported HTTP method: {method}")

        return response.json()
    except Exception as e:
        logger.error(f"Error connecting to snapd API: {e}")
        return {"type": "error", "result": {"message": str(e)}}
    finally:
        session.close()


def is_snap_installed(snap_name: str) -> bool:
    """Check if a snap is installed using the snapd API."""
    try:
        response = connect_to_snapd("GET", f"/v2/snaps/{snap_name}")

        # If the response type is "sync" and status code is 200, the snap exists
        if response.get("type") == "sync" and response.get("status-code") == 200:
            logger.info(f"{snap_name} snap is already installed")
            return True

        # If we get a 404, the snap is not installed
        if response.get("status-code") == 404:
            logger.info(f"{snap_name} snap is not installed")
            return False

        # Unexpected response
        logger.warning(f"Unexpected response checking for {snap_name}: {response}")
        return False
    except Exception as e:
        logger.error(f"Error checking if {snap_name} is installed: {e}")
        return False


def install_snap(
    snap_name: str,
) -> bool:
    """Install a snap using the snapd API."""
    try:
        logger.info(f"Installing {snap_name} snap...")
        data = {"action": "install", "channel": "stable"}

        response = connect_to_snapd("POST", f"/v2/snaps/{snap_name}", data)

        # If it's an async operation, it's started successfully
        if response.get("type") == "async":
            change_id = response.get("change")
            logger.info(f"{snap_name} installation started (change ID: {change_id})")

            # Wait for the installation to complete
            while True:
                change_response = connect_to_snapd("GET", f"/v2/changes/{change_id}")
                status = change_response.get("result", {}).get("status")

                if status == "Done":
                    logger.info(f"{snap_name} installation completed successfully")
                    return True
                elif status in ["Error", "Abort"]:
                    logger.error(f"{snap_name} installation failed: {change_response}")
                    return False

                # Wait before checking again
                time.sleep(5)
        else:
            logger.error(f"Failed to start {snap_name} installation: {response}")
            return False
    except Exception as e:
        logger.error(f"Error installing {snap_name}: {e}")
        return False


# Convenience functions for specific snaps
def is_microk8s_installed() -> bool:
    """Check if MicroK8s snap is installed."""
    return is_snap_installed("microk8s")


def install_microk8s() -> bool:
    """Install MicroK8s snap."""
    return install_snap("microk8s")


def is_avahi_installed() -> bool:
    """Check if Avahi snap is installed."""
    return is_snap_installed("avahi")


def install_avahi() -> bool:
    """Install Avahi snap."""
    return install_snap("avahi")


def check_microk8s_ready() -> bool:
    """
    Run microk8s status --wait-ready to confirm the cluster is ready.

    Returns:
        bool: True if MicroK8s is ready, False otherwise
    """
    try:
        logger.info("Waiting for MicroK8s to be ready...")
        result = subprocess.run(
            ["microk8s", "status", "--wait-ready"],
            capture_output=True,
            text=True,
            check=False,
        )

        if result.returncode == 0:
            logger.info("MicroK8s is ready")
            return True
        else:
            logger.error(f"MicroK8s readiness check failed: {result.stderr}")
            return False
    except Exception as e:
        logger.error(f"Error checking MicroK8s readiness: {e}")
        return False


# Broadcast service with Avahi
def setup_avahi_service() -> bool:

    # Constants
    AVAHI_DBUS_NAME = "org.freedesktop.Avahi"
    AVAHI_DBUS_PATH_SERVER = "/"
    AVAHI_DBUS_INTERFACE_SERVER = "org.freedesktop.Avahi.Server"
    AVAHI_DBUS_INTERFACE_ENTRY_GROUP = "org.freedesktop.Avahi.EntryGroup"

    try:

        bus = SystemMessageBus()
        # Get the Avahi server object
        avahi_server = bus.get_proxy(  # type: ignore
            AVAHI_DBUS_NAME, AVAHI_DBUS_PATH_SERVER, AVAHI_DBUS_INTERFACE_SERVER
        )

        # Create a new entry group
        entry_group_path = avahi_server.EntryGroupNew()  # type: ignore
        entry_group = bus.get_proxy(  # type: ignore
            AVAHI_DBUS_NAME, entry_group_path, AVAHI_DBUS_INTERFACE_ENTRY_GROUP  # type: ignore
        )

        # Add an HTTP service (port 80, no TXT records)
        entry_group.AddService(  # type: ignore
            -1,  # Interface index (-1 for all)
            -1,  # Protocol (-1 for IPv4+IPv6)
            UInt32(0),  # Flags (0 for default)
            "microk8s",  # Service name
            "_http._tcp",  # Service type
            "",  # Domain (empty for local)
            "",  # Host (empty for default)
            UInt16(80),  # Port
            list[dict[str, Any]](),  # TXT records (empty list)
        )

        # Commit the service
        entry_group.Commit()  # type: ignore

        logger.info("Avahi service setup completed successfully")
        return True
    except Exception as e:
        logger.error(f"Failed to set up Avahi service: {e}")
        return False


def setup_system() -> bool:
    """
    Main function to set up required system components:
    - Check if MicroK8s is installed
    - Install MicroK8s if needed
    - Wait for MicroK8s to be ready
    - Check if Avahi is installed
    - Install Avahi if needed

    Returns:
        bool: True if setup is successful, False otherwise
    """
    success = True

    # Set up MicroK8s
    if not is_microk8s_installed():
        logger.info("MicroK8s not found. Installing...")
        if install_microk8s():
            logger.info("MicroK8s installed successfully")
            # Wait for MicroK8s to be ready
            if not check_microk8s_ready():
                logger.warning(
                    "MicroK8s installation completed but cluster is not ready"
                )
                success = False
        else:
            logger.error("Failed to install MicroK8s")
            success = False
    else:
        logger.info("MicroK8s is already installed")
        # Check readiness for pre-installed MicroK8s as well
        if not check_microk8s_ready():
            success = False

    # Set up Avahi
    if not is_avahi_installed():
        logger.info("Avahi not found. Installing...")
        if install_avahi():
            logger.info("Avahi installed successfully")
        else:
            logger.error("Failed to install Avahi")
            success = False
    else:
        logger.info("Avahi is already installed")

    return success


if __name__ == "__main__":
    # Configure logging for standalone use
    logging.basicConfig(level=logging.INFO)
    setup_system()
