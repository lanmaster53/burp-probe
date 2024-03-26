from flask import g, request, abort, redirect, url_for, make_response
from burp_probe.constants import UserTypes
from functools import wraps

def login_required(func):
    @wraps(func)
    def wrapped(*args, **kwargs):
        if g.user:
            return func(*args, **kwargs)
        abort(401)
        #return redirect(url_for('reporting.login', next=request.url))
    return wrapped

def roles_required(*roles):
    def wrapper(func):
        @wraps(func)
        def wrapped(*args, **kwargs):
            if UserTypes[g.user.type] not in roles:
                return abort(403)
            return func(*args, **kwargs)
        return wrapped
    return wrapper

def hx_trigger(event):
    def wrapper(func):
        @wraps(func)
        def wrapped(*args, **kwargs):
            response = make_response(func(*args, **kwargs))
            response.headers['HX-Trigger'] = event
            return response
        return wrapped
    return wrapper
