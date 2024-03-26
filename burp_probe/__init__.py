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
        return json.dumps(json.loads(data), indent=4)

    from burp_probe.views.core import blp as CoreBlueprint
    app.register_blueprint(CoreBlueprint)

    @app.cli.command('init')
    def init_data():
        from burp_probe import models
        db.create_all()
        # initialization logic here (optional)
        app.logger.info('Database initialized.')

    @app.cli.command('migrate')
    def migrate_data():
        # migration logic here
        app.logger.info('Migration complete.')

    return app