#!/usr/bin/env python

import sys
import logging
from time import sleep

from securecscc import ApplicationFactory


def _logger():
    logger = logging.getLogger('securecscc')
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    handler = logging.StreamHandler()
    handler.setFormatter(formatter)

    logger.addHandler(handler)
    logger.setLevel(logging.INFO)

    return logger


def main():
    application_factory = ApplicationFactory()
    sysdig_secure_client = application_factory.sysdig_secure_client()
    action = application_factory.create_finding_from_sysdig_secure_event_action()

    logger = _logger()

    while True:
        logger.info('Querying events from Sysdig Secure')
        for event in sysdig_secure_client.events_happened_on_last_minute():
            logger.info('Publishing on Google Security Command')
            try:
                result = action.run(event)
                logger.info(result)
            except Exception as ex:
                logger.error(ex)

        sleep(60)


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
