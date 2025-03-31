import logging
import time

from systemd.daemon import notify

# Configure logging
logging.basicConfig(
    filename="/var/log/auto_microk8s_cluster.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)


def main():
    """Main function for the service."""
    logging.info("Auto MicroK8s Cluster service started.")
    notify("READY=1")  # Notify systemd that the service is ready

    try:
        while True:
            # Perform the service's main task here
            logging.info("Service is running...")
            time.sleep(10)  # Sleep for 10 seconds
    except KeyboardInterrupt:
        logging.info("Auto MicroK8s Cluster service stopped.")
    except Exception as e:
        logging.error(f"Service encountered an error: {e}")
    finally:
        notify("STOPPING=1")  # Notify systemd that the service is stopping


if __name__ == "__main__":
    main()
