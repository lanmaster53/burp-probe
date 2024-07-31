from flask import Flask
from flask.logging import default_handler
from burp_probe.extensions import db, bcrypt, scheduler
from burp_probe.helpers import render_partial
import json
import logging
import os

default_handler.setFormatter(logging.Formatter('[%(asctime)s] %(levelname)s from %(name)s in %(module)s: %(message)s'))

# ----------------------------
# Application Factory Function
# ----------------------------

def create_app():

    # Create the Flask application
    app = Flask(__name__, static_url_path='')

    # Configure the Flask application
    config_class = os.getenv('CONFIG', default='Production')
    app.config.from_object('burp_probe.config.{}'.format(config_class.title()))
    app.logger.info(f"Burp Probe starting in {config_class} mode.")

    db.init_app(app)
    bcrypt.init_app(app)
    scheduler.init_app(app)
    scheduler.start()

    from burp_probe.tasks import scan_sync

    def finalize(arg):
        if arg is None:
            return ''
        return arg

    # Convert None types to empty strings in the template context
    app.jinja_env.finalize = finalize
    # Clean up white space left behind by jinja template code
    app.jinja_env.trim_blocks = True
    app.jinja_env.lstrip_blocks = True

    app.add_template_global(render_partial)

    @app.template_filter('ppjson')
    def ppjson_filter(data):
        '''
        Use: {{ json_string|ppjson }}
        '''
        if type(data) == str:
            data = json.loads(data)
        return json.dumps(data, indent=4)

    from burp_probe.routes.auth import blp as AuthBlueprint
    app.register_blueprint(AuthBlueprint)
    from burp_probe.routes.core import blp as CoreBlueprint
    app.register_blueprint(CoreBlueprint)

    @app.cli.command('init')
    def init_data():
        from burp_probe import models
        db.create_all()
        app.logger.info('Database initialized.')
        # Initialization logic here (optional)
        from burp_probe.constants import UserTypes
        import string
        import secrets
        characters = string.ascii_letters + string.digits
        password = ''.join(secrets.choice(characters) for i in range(15))
        user = models.User(
            email='admin@burp-probe.com',
            name='Admin User',
            password=password,
            type=UserTypes.ADMIN
        )
        db.session.add(user)
        db.session.commit()
        app.logger.info('Administrator user initialized.')
        app.logger.info(f"Email: {user.email}")
        app.logger.info(f"Password: {password}")
        app.logger.info(f"{'*'*8} THIS INFORMATION WILL NOT BE SHOWN AGAIN! {'*'*8}")

    @app.cli.command('migrate')
    def migrate_data():
        # Migration logic here (optional)
        app.logger.info('Migration complete.')

    return app
