#!/usr/bin/env python

import sys
import logging
import argparse
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


def parse_args():
    parser = argparse.ArgumentParser(description='Poll Sysdig Secure for events and store as findings in Google Cloud Security Command Center')
    parser.add_argument('--duration', '-d', type=int, default=60, help='Time between queries (default: 60)')

    return parser.parse_args()


def main():
    args = parse_args()
    application_factory = ApplicationFactory()
    sysdig_secure_client = application_factory.sysdig_secure_client()
    action = application_factory.create_finding_from_sysdig_secure_event_action()

    logger = _logger()

    while True:
        logger.info('Querying events from Sysdig Secure')
        for event in sysdig_secure_client.events_happened_on_last(args.duration):
            logger.info('Publishing to Google Security Command')
            try:
                result = action.run(event)
                logger.info(result.to_dict())
            except Exception as ex:
                logger.error(ex)

        sleep(args.duration)


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
