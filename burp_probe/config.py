import os

BASEDIR = os.path.abspath(os.path.dirname(__file__))
DATADIR = os.path.join(BASEDIR, '../data')


class BaseConfig(object):

    SQLALCHEMY_DATABASE_URI = 'sqlite:///' + os.path.join(DATADIR, 'burp-probe.db')


class Development(BaseConfig):

    DEBUG = True
    TEMPLATES_AUTO_RELOAD = True
    SECRET_KEY = 'development key'


class Production(BaseConfig):

    import secrets

    DEBUG = False
    SECRET_KEY = secrets.token_hex()
