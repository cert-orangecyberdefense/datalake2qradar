import logging
import os
import schedule
import time
import config
from queue import Queue
from constants import CONNECTOR_CONSUMER_COUNT
from Datalake2Qradar import Datalake2Qradar, QradarReference
from dotenv import load_dotenv

load_dotenv()

QRADAR_URL = os.environ["QRADAR_URL"]
QRADAR_TOKEN = os.environ["QRADAR_TOKEN"]
QRADAR_SSL_VERIFY = os.environ["QRADAR_SSL_VERIFY"]
QRADAR_REFERENCE_NAME = os.environ["QRADAR_REFERENCE_NAME"]


def _build_logger():
    logger = logging.getLogger("datalake2qradar")
    logger.setLevel(logging.INFO)
    if config.verbose_log:
        logger.setLevel(logging.DEBUG)
    handler = logging.FileHandler(os.environ["LOG_FILE"], mode="a")
    handler.setLevel(logging.INFO)
    if config.verbose_log:
        handler.setLevel(logging.DEBUG)
    formatter = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )
    handler.setFormatter(formatter)
    logger.addHandler(handler)

    return logger


def main():
    # create reference_set instance
    reference_set = QradarReference(
        QRADAR_URL,
        QRADAR_TOKEN,
        QRADAR_REFERENCE_NAME,
        True if QRADAR_SSL_VERIFY == "true" else False,
    )

    # create queue
    queue = Queue(maxsize=2 * CONNECTOR_CONSUMER_COUNT)

    # create the connector
    datalake2qradar = Datalake2Qradar(
        reference_set, queue, CONNECTOR_CONSUMER_COUNT, logger
    )
    if config.run_as_cron:
        schedule.every(config.upload_frequency).hours.do(
            datalake2qradar.uploadIndicatorsToQradar
        )
        while True:
            schedule.run_pending()
            time.sleep(1)
    else:
        datalake2qradar.uploadIndicatorsToQradar()


if __name__ == "__main__":
    logger = _build_logger()

    logger.info("Start Datalake2Qradar connector")
    main()
    logger.info("End Datalake2Qradar connector")
