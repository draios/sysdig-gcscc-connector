import http

from flask import Flask, jsonify, request

import securecscc

app = Flask(__name__)

factory = securecscc.ApplicationFactory()
ACTION = factory.create_finding_from_event_action()

settings = factory.settings()


@app.route('/', methods=['POST'])
def create_finding():
    raw = request.get_json()

    finding = ACTION.run(raw)

    return jsonify(finding), http.client.CREATED


if __name__ == '__main__':
    app.run(debug=True)
