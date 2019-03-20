#!/usr/bin/env python

import argparse

import securecscc


def main():
    args = _parse_arguments()

    factory = securecscc.ApplicationFactory()

    notification_channel = factory.create_cscc_notification_channel_action().run(
        args.webhook_url,
        args.webhook_authentication_token
    )

    print('The Google Cloud Security Center notification channel has been created on Sysdig Secure')
    print('Please export its ID\'s before starting to run the integration:')
    print('')
    print('export WEBHOOK_URL="{}"'.format(notification_channel['options']['url']))
    print('export WEBHOOK_AUTHENTICATION_TOKEN="{}"'.format(notification_channel['options']['additionalHeaders']['Authorization']))


def _parse_arguments():
    parser = argparse.ArgumentParser(description='Create notification channel in Sysdig Secure for Google Cloud Security Command Center')
    parser.add_argument('webhook_url', help='The URL where the webhook is listening')
    parser.add_argument('webhook_authentication_token',  help='The authentication token that webhook will be use for accepting events')

    return parser.parse_args()


if __name__ == '__main__':
    main()
