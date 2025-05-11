import argparse
import logging
import time

parser = argparse.ArgumentParser()
parser.add_argument(
    "-log",
    "--loglevel",
    default="info",
    help="Provide logging level. Example --loglevel debug, default=warning",
)

args = parser.parse_args()


# Configure logging
logger = logging.getLogger(__name__)
logging.basicConfig(level=args.loglevel.upper())
logger.info("Logging now setup.")


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
