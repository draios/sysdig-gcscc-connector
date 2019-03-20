import http

from flask import Flask, jsonify, request
from connectors.flask_helpers import webhook_authentication_required, HealthView

import securecscc

app = Flask(__name__)
app.add_url_rule('/health', view_func=HealthView.as_view('health'))

factory = securecscc.ApplicationFactory()
ACTION = factory.create_finding_from_falco_alarm_action()

settings = factory.settings()


@app.route('/events', methods=['POST'])
@webhook_authentication_required(settings.webhook_authentication_token())
def create_finding():
    raw = request.get_json()

    finding = ACTION.run(raw)

    return jsonify(finding.to_dict()), http.client.CREATED


if __name__ == '__main__':
    app.run(debug=True)
