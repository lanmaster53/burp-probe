from flask import g, session, request
from burp_probe.helpers import render_partial
from burp_probe.models import User

# ------------------
# Request Middleware
# ------------------

def load_user():
    g.user = None
    if user_id := session.get('user_id'):
        g.user = User.query.get(user_id)

def strip_empty_params():
    if obj := request.form:
        data = dict(obj)
        for field in list(data):
            if data[field] == '':
                data.pop(field)
        request.form = data

# -------------------
# Response Middleware
# -------------------

def modify_response(response):
    # Logic to manipulate the response here
    # `request` context is available
    response = manage_flashes(response)
    return response

def manage_flashes(response):
    # The `HX-Request` header indicates that the request was made with HTMX
    if 'HX-Request' not in request.headers:
        return response
    # Refactor HTTP redirections as client-side redirections
    if 300 <= response.status_code < 400:
        response.headers['HX-Redirect'] = response.location
        response.status_code = 204
        return response
    # Ignore client-side redirection because HTMX drops OOB swaps
    if 'HX-Redirect' in response.headers:
        return response
    flash_content = render_partial('partials/flash.html')
    # Add to the response
    response.data = response.data + flash_content.encode()
    return response
