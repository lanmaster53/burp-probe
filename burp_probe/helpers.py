from flask import render_template, get_template_attribute
from markupsafe import Markup

def render_partial(name, **context):
	return Markup(render_template(name, **context))

def render_macro(template_name, macro_name, **context):
    return Markup(get_template_attribute(template_name, macro_name)(**context))
