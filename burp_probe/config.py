import os
import secrets

BASEDIR = os.path.abspath(os.path.dirname(__file__))
DATADIR = os.path.join(BASEDIR, '../data')


class BaseConfig(object):

    DEBUG = False
    TESTING = False
    SQLALCHEMY_DATABASE_URI = 'sqlite:///' + os.path.join(DATADIR, 'burp-probe.db')
    SCHEDULER_API_ENABLED = False


class Production(BaseConfig):

    SECRET_KEY = secrets.token_hex()


class Development(BaseConfig):

    DEBUG = True
    TEMPLATES_AUTO_RELOAD = True
    SECRET_KEY = 'DEVELOPMENT_KEY'


class Test(BaseConfig):

    DEBUG = True
    TESTING = True
    SECRET_KEY = 'TESTING_KEY'
