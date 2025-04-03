import logging
import time

# Configure logging
logger = logging.getLogger(__name__)


def main():
    """Main function for the service."""
    logger.info("Auto MicroK8s Cluster service started.")

    try:
        while True:
            # Perform the service's main task here
            logger.info("Service is running...")
            time.sleep(10)  # Sleep for 10 seconds
    except KeyboardInterrupt:
        logger.info("Auto MicroK8s Cluster service stopped.")
    except Exception as e:
        logger.error(f"Service encountered an error: {e}")


if __name__ == "__main__":
    main()
