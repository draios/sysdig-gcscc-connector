import os
import json


def _read_file(filename):
    current_directory = os.path.dirname(os.path.realpath(__file__))
    event_file = os.path.join(current_directory, filename)

    with open(event_file, 'rb') as event:
        return event.read()


def event():
    return json.loads(_read_file('event.json'))


def event_host():
    return json.loads(_read_file('event_host.json'))


def event_falco():
    return json.loads(_read_file('event_falco.json'))


def event_falco_k8s():
    return json.loads(_read_file('event_falco_k8s.json'))


def payload_from_webhook():
    return _read_file('event_webhook.json')


def payload_from_falco():
    return _read_file('event_falco.json')


def event_in_webhook():
    payload = json.loads(payload_from_webhook())

    return payload['entities'][0]['policyEvents'][0]
