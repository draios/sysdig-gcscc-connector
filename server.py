import http

from flask import Flask, jsonify, request

import securecscc

app = Flask(__name__)

factory = securecscc.ApplicationFactory()
ACTION = factory.create_finding_from_event_action()

settings = factory.settings()


@app.before_first_request
def setup_webhook():
    factory.create_cscc_notification_channel_action().run()


@app.route('/')
def hello():
    return jsonify({
        'message': 'Hello World'
    })


@app.route('/events', methods=['POST'])
def create_finding():
    if not _is_authorized(request):
        return jsonify({'message': 'Not authorized'}), http.client.FORBIDDEN

    raw = request.get_json()
    events = raw['entities'][0]['policyEvents']

    result = [ACTION.run(event) for event in events]

    return jsonify(result), http.client.CREATED


def _is_authorized(request):
    if 'Authorization' not in request.headers:
        return False

    return request.headers['Authorization'] == settings.webhook_authentication_token()


if __name__ == '__main__':
    app.run(debug=True)
