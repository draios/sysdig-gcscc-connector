#!/usr/bin/env bash
set -e

if [ "$1" = 'polling_runner' ]; then
    exec python polling_runner.py
fi

if [ "$1" = 'webhook_server' ]; then
    exec gunicorn -b 0.0.0.0:8080 webhook_server:app
fi

if [ "$1" = 'falco_server' ]; then
    exec gunicorn -b 0.0.0.0:8080 falco_server:app
fi

exec "$@"
