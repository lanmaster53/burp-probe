from flask import Flask
from flask_bcrypt import Bcrypt
from flask_sqlalchemy import SQLAlchemy
from flask_apscheduler import APScheduler
from burp_probe.helpers import render_partial
import json

db = SQLAlchemy()
bcrypt = Bcrypt()
scheduler = APScheduler()

def create_app(config):

    app = Flask(__name__, static_url_path='')
    app.config.from_object('burp_probe.config.{}'.format(config.title()))
    app.logger.info(f"Burp Probe starting in {config} mode.")

    db.init_app(app)
    bcrypt.init_app(app)
    scheduler.init_app(app)
    scheduler.start()

    from burp_probe.tasks import scan_sync

    def finalize(arg):
        if arg is None:
            return ''
        return arg

    # converts None types to empty strings in the template context
    app.jinja_env.finalize = finalize
    # clean up white space left behind by jinja template code
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

    from burp_probe.views.auth import blp as AuthBlueprint
    app.register_blueprint(AuthBlueprint)
    from burp_probe.views.core import blp as CoreBlueprint
    app.register_blueprint(CoreBlueprint)

    @app.cli.command('init')
    def init_data():
        from burp_probe import models
        db.create_all()
        app.logger.info('Database initialized.')
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
        # migration logic here
        app.logger.info('Migration complete.')

    return app
