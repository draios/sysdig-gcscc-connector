import http
from functools import wraps

from flask import jsonify, request, views


class HealthView(views.View):
    methods = ['GET']

    def dispatch_request(self):
        return jsonify({
            'message': 'Application is running',
            'success': True
        })


def webhook_authentication_required(authentication_token):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not _is_authorized(request, authentication_token):
                return jsonify({'message': 'Not authorized'}), http.client.FORBIDDEN

            return f(*args, **kwargs)

        return decorated_function

    return decorator


def _is_authorized(request, authentication_token):
    if 'Authorization' not in request.headers:
        return False

    return request.headers['Authorization'] == authentication_token
