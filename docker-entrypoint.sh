#!/usr/bin/env bash
set -e

if [ "$1" = 'sysdig_secure_poller' ]; then
    shift
    exec python ./connectors/sysdig_secure_poller.py "$@"
fi

if [ "$1" = 'sysdig_secure_webhook' ]; then
    exec gunicorn -b 0.0.0.0:8080 connectors.sysdig_secure_webhook:app
fi

if [ "$1" = 'falco_webhook' ]; then
    exec gunicorn -b 0.0.0.0:8080 connectors.falco_webhook:app
fi

if [ "$1" = 'create_notification_channel' ]; then
    shift
    exec python ./scripts/create_notification_channel.py "$@"
fi

if [ "$1" = 'create_security_source' ]; then
    shift
    exec python ./scripts/create_security_source.py "$@"
fi


exec "$@"
