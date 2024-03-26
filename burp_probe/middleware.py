from flask import g, session, request
from burp_probe.helpers import render_partial
from burp_probe.models import User

# request middleware

def load_user():
    g.user = None
    if session.get('user_id'):
        g.user = User.query.get(session.get('user_id'))

# response middleware

def modify_response(response):
    # logic to manipulate the response here
    # `request` context is available
    response = manage_flashes(response)
    return response

def manage_flashes(response):
    # the HX-Request header indicates that the request was made with HTMX
    if 'HX-Request' not in request.headers:
        return response
    # ignore HTTP redirections because HTMX cannot read the body
    if 300 <= response.status_code < 400:
        return response
    # ignore client-side redirection because HTMX drops OOB swaps
    if 'HX-Redirect' in response.headers:
        return response
    flash_content = render_partial('partials/flash.html')
    # add to the response
    response.data = response.data + flash_content.encode()
    return response
