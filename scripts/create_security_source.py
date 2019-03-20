#!/usr/bin/env python

import argparse

import securecscc


def main():
    args = _parse_arguments()

    factory = securecscc.ApplicationFactory()

    if args.security_source == 'falco':
        security_source = factory.create_security_source_action().run(
            'Falco',
            'Falco is an open source project for intrusion and abnormality detection for Cloud Native platforms such as Kubernetes, Mesosphere, and Cloud Foundry. Detect abnormal application behavior. Alert via Slack, Fluentd, NATS, and more. Protect your platform by taking action through serverless (FaaS) frameworks, or other automation.'
        )
    elif args.security_source == 'sysdig_secure':
        security_source = factory.create_security_source_action().run(
            'Sysdig Secure',
            '''Sysdig is a unified platform for container and microservices monitoring, troubleshooting, security and forensics.
With Secure you protect and assure your applications.
We bring together image scanning, run-time protection, and forensics to identify vulnerabilities, block threats, enforce compliance, and audit activity across your microservices.'''
        )

    if security_source is not None:
        print('The security source for {} has been successfully created'.format(security_source.display_name))
        print('Please export its ID before starting to run the integration:')
        print('')
        print('export SOURCE_ID="{}"'.format(security_source.name.split('/')[-1]))


def _parse_arguments():
    parser = argparse.ArgumentParser(description='Create security source in Google Cloud Security Command Center')
    parser.add_argument('security_source', choices=['falco', 'sysdig_secure'], help='The source Falco or Sysdig Secure which we are going to create')

    return parser.parse_args()


if __name__ == '__main__':
    main()
