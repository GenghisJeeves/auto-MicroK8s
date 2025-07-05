import logging
import re
import subprocess
import time
from typing import Any

from auto_microk8s_cluster.neighbours import get_trusted_neighbours, send_secure_message

# Configure logging
logger = logging.getLogger(__name__)

# Constants
JOIN_TIMEOUT = 300  # seconds
RETRY_INTERVAL = 10  # seconds
CLUSTER_STATUS_CHECK_INTERVAL = 30  # seconds


def run_command(cmd: list[str], timeout: int = 60) -> tuple[bool, str]:
    """
    Run a shell command and return its outcome

    Args:
        cmd: Command to run as a list of strings
        timeout: Command timeout in seconds

    Returns:
        Tuple of (success, output)
    """
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        if result.returncode == 0:
            return True, result.stdout
        else:
            logger.error(f"Command failed: {' '.join(cmd)}")
            logger.error(f"Error output: {result.stderr}")
            return False, result.stderr
    except subprocess.TimeoutExpired:
        logger.error(f"Command timed out: {' '.join(cmd)}")
        return False, "Command timed out"
    except Exception as e:
        logger.error(f"Error running command: {e}")
        return False, str(e)


def extract_join_command(output: str) -> str | None:
    """
    Extract the join command from the microk8s add-node output

    Args:
        output: Output string from microk8s add-node

    Returns:
        The join command string or None if not found
    """
    # Look for the join command pattern
    pattern = r"microk8s join (\S+)"
    match = re.search(pattern, output)

    if match:
        return match.group(0)
    else:
        logger.error("Could not extract join command from output")
        return None


def build_microk8s_cluster() -> bool:
    """
    Build a MicroK8s cluster with trusted neighbours

    Returns:
        True if the cluster was successfully built or joined, False otherwise
    """
    logger.info("Starting MicroK8s cluster build process")

    # Get all trusted neighbours
    trusted_neighbours = get_trusted_neighbours()
    if not trusted_neighbours:
        logger.warning("No trusted neighbours found. Cannot build a cluster.")
        return False
    elif len(trusted_neighbours) < 2:
        logger.warning(
            "Not enough trusted neighbours to form a cluster. At least 2 are required."
        )
        return False
    else:
        logger.info(
            f"Found {len(trusted_neighbours)} trusted neighbours: "
            + ", ".join([f"{n.name} ({n.ip_address})" for n in trusted_neighbours])
        )

        # As this node has started the cluster formation, it will be the master node

        # Send the join command to all trusted neighbours
        logger.info(
            f"Sending join command to {len(trusted_neighbours)} trusted neighbours"
        )

        for neighbour in trusted_neighbours:

            # Run microk8s add-node command to generate joining info
            success, output = run_command(["microk8s", "add-node"], timeout=60)
            if not success:
                logger.error("Failed to generate cluster joining information")
                return False

            logger.debug(f"Add-node output: {output}")

            # Extract the join command
            join_command = extract_join_command(output)
            if not join_command:
                return False

            # Send join command message
            message: dict[str, Any] = {
                "type": "cluster_join",
                "command": join_command,
                "timestamp": time.time(),
            }

            response = send_secure_message(neighbour, message)
            if response:
                logger.info(
                    f"Sent join command to {neighbour.name} ({neighbour.ip_address})"
                )
            else:
                logger.warning(
                    f"Failed to send join command to {neighbour.name} ({neighbour.ip_address})"
                )

        # Monitor cluster formation
        logger.info("Monitoring cluster formation...")
        start_time = time.time()

        while time.time() - start_time < JOIN_TIMEOUT:
            success, output = run_command(
                ["microk8s", "kubectl", "get", "nodes"], timeout=30
            )
            if success:
                # Count the number of nodes that have joined
                nodes = [
                    line
                    for line in output.split("\n")
                    if line.strip() and "NAME" not in line
                ]
                logger.info(f"Current cluster state: {len(nodes)} nodes")
                if (
                    len(nodes) >= len(trusted_neighbours) + 1
                ):  # All neighbours + this node
                    logger.info("All nodes have joined the cluster successfully")
                    return True

            time.sleep(CLUSTER_STATUS_CHECK_INTERVAL)

        logger.warning("Timeout waiting for all nodes to join the cluster")
        return False


def join_microk8s_cluster(join_command: str) -> bool:
    """Join this MicroK8s node to an existing cluster"""
    logger.info(f"Joining MicroK8s cluster with join command: {join_command}")
    success, output = run_command(join_command.split(), timeout=60)
    if success:
        logger.info("Successfully joined the MicroK8s cluster")
        return True
    else:
        logger.error(f"Failed to join the cluster: {output}")
        return False


if __name__ == "__main__":
    # Set up basic logging when run directly
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )

    # Build the cluster
    result = build_microk8s_cluster()
    print(f"Cluster build {'successful' if result else 'failed'}")
