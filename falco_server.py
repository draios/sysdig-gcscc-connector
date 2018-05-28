import http

from flask import Flask, jsonify, request
from flask_utils import webhook_authentication_required

import securecscc

app = Flask(__name__)

factory = securecscc.ApplicationFactory()
ACTION = factory.create_finding_from_falco_alarm_action()

settings = factory.settings()


@app.route('/events', methods=['POST'])
@webhook_authentication_required(settings.webhook_authentication_token())
def create_finding():
    raw = request.get_json()

    finding = ACTION.run(raw)

    return jsonify(finding), http.client.CREATED


if __name__ == '__main__':
    app.run(debug=True)
