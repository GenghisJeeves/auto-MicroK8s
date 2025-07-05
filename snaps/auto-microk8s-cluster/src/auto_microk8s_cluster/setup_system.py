import logging
import subprocess
import time
from typing import Any

import requests_unixsocket

from .avahi import check_hostname, set_hostname

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


def install_snap(snap_name: str, channel: str = "stable") -> bool:
    """Install a snap using the snapd API."""
    try:
        logger.info(f"Installing {snap_name} snap...")
        data = {"action": "install", "channel": channel}

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
    return install_snap("microk8s", "1.32-strict")


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


# Broadcast service with Avahi using sdbus
def setup_avahi_service() -> bool:
    """
    Set up an Avahi (mDNS) service for MicroK8s discovery using sdbus.

    Returns:
        bool: True if successful, False otherwise
    """
    avahi_setup_success = False
    if check_hostname("microk8s"):
        logger.info("Hostname is already set to 'microk8s'")
        avahi_setup_success = True
    else:
        avahi_setup_success = set_hostname("microk8s")

    return avahi_setup_success


def setup_system() -> bool:
    """
    Main function to set up required system components:
    - Check if MicroK8s is installed
    - Install MicroK8s if needed
    - Wait for MicroK8s to be ready
    - Check if Avahi is installed
    - Install Avahi if needed
    - Set up Avahi service for discovery

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
            # Set up Avahi service after installation
            if not setup_avahi_service():
                logger.warning("Failed to set up Avahi service")
                success = False
        else:
            logger.error("Failed to install Avahi")
            success = False
    else:
        logger.info("Avahi is already installed")
        # Set up Avahi service for pre-installed Avahi as well
        if not setup_avahi_service():
            logger.warning("Failed to set up Avahi service")
            success = False

    return success


def hold_snap_updates(snap_name: str, duration: str = "forever") -> bool:
    """
    Prevent a snap from receiving automatic updates for a specified duration.

    Args:
        snap_name: Name of the snap to hold updates for
        duration: Duration for the hold (e.g., "1h", "2d", "1w", "forever")

    Returns:
        bool: True if successful, False otherwise
    """
    try:
        logger.info(f"Holding updates for {snap_name} snap for duration: {duration}")

        # Create the request data
        data: dict[str, str | list[str]] = {
            "action": "refresh",
            "snap-ids": [snap_name],
            "hold": duration,
        }

        # Send the request to the snapd API
        response = connect_to_snapd("POST", "/v2/snaps", data)

        # Check if the request was successful
        if response.get("type") == "async":
            change_id = response.get("change")
            logger.info(
                f"Hold request initiated for {snap_name} (change ID: {change_id})"
            )

            # Wait for the operation to complete
            while True:
                change_response = connect_to_snapd("GET", f"/v2/changes/{change_id}")
                status = change_response.get("result", {}).get("status")

                if status == "Done":
                    logger.info(f"Successfully held updates for {snap_name} {duration}")
                    return True
                elif status in ["Error", "Abort"]:
                    logger.error(
                        f"Failed to hold updates for {snap_name}: {change_response}"
                    )
                    return False

                # Wait before checking again
                time.sleep(2)
        else:
            logger.error(f"Failed to initiate hold for {snap_name}: {response}")
            return False
    except Exception as e:
        logger.error(f"Error holding updates for {snap_name}: {e}")
        return False


def hold_microk8s_updates(duration: str = "forever") -> bool:
    """
    Prevent MicroK8s from receiving automatic updates.

    Args:
        duration: Duration for the hold (e.g., "1h", "2d", "1w", "forever")

    Returns:
        bool: True if successful, False otherwise
    """
    logger.info(f"Holding MicroK8s updates for {duration}")
    return hold_snap_updates("microk8s", duration)


if __name__ == "__main__":
    # Configure logging for standalone use
    logging.basicConfig(level=logging.INFO)
    setup_system()
