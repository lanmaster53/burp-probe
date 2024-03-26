from burp_probe import db, bcrypt
from burp_probe.services.burp import BurpProApi
from sqlalchemy import UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship
from datetime import datetime, timezone
import binascii
import json
import uuid

# https://github.com/pallets-eco/flask-sqlalchemy/issues/1140

def get_current_utc_time():
    return datetime.now(timezone.utc)

def get_local_from_utc(dtg):
    return dtg.replace(tzinfo=timezone.utc).astimezone(tz=None)

def get_guid():
    return str(uuid.uuid4())


class BaseModel(db.Model):
    __abstract__ = True
    id: Mapped[str] = mapped_column(db.String(36), primary_key=True, default=get_guid)
    created: Mapped[str] = mapped_column(db.DateTime, nullable=False, default=get_current_utc_time)

    def attr_is_nullable(self, s):
        return self.__table__.columns[s].nullable

    @property
    def created_as_string(self):
        return get_local_from_utc(self.created).strftime("%Y-%m-%d %H:%M:%S")


class User(BaseModel):
    __tablename__ = 'users'
    email: Mapped[str] = mapped_column(db.String(), nullable=False, unique=True)
    name: Mapped[str] = mapped_column(db.String(), nullable=False)
    password_hash: Mapped[str] = mapped_column(db.String(), nullable=False)
    type: Mapped[str] = mapped_column(db.String(), nullable=False)

    @property
    def password(self):
        raise AttributeError('password: write-only field')

    @password.setter
    def password(self, password):
        self.password_hash = bcrypt.generate_password_hash(binascii.hexlify(password.encode()))

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, binascii.hexlify(password.encode()))

    def __repr__(self):
        return f"<User '{self.email}'>"


class Scan(BaseModel):
    __tablename__ = 'scans'
    name: Mapped[str] = mapped_column(db.String(), nullable=False, unique=True)
    description: Mapped[str] = mapped_column(db.String(), nullable=True)
    configuration: Mapped[str] = mapped_column(db.String(), nullable=True) # JSON config stored as string
    status: Mapped[str] = mapped_column(db.String(), nullable=False)
    result: Mapped[str] = mapped_column(db.String(), nullable=True) # JSON result stored as a string
    task_id: Mapped[int] = mapped_column(db.Integer(), nullable=True)
    node_id: Mapped[str] = mapped_column(db.String(36), db.ForeignKey('nodes.id'), nullable=False)
    node: Mapped['Node'] = relationship('Node', back_populates='scans', foreign_keys=[node_id])

    @staticmethod
    def get_assets():
        assets = []
        for scan in Scan.query.all():
            scan_config = json.loads(scan.configuration)
            for url in scan_config['urls']:
                asset = next((a for a in assets if a['url'] == url), None)
                if asset:
                    asset['count'] += 1
                else:
                    asset = {
                        'url': url,
                        'count': 1,
                    }
                    assets.append(asset)
        return assets

    def __repr__(self):
        return f"<Scan '{self.name}'>"


class Node(BaseModel):
    __tablename__ = 'nodes'
    #__table_args__ = tuple(UniqueConstraint('protocol', 'hostname', 'port'))
    name: Mapped[str] = mapped_column(db.String(), nullable=False, unique=True)
    description: Mapped[str] = mapped_column(db.String(), nullable=True)
    protocol: Mapped[str] = mapped_column(db.String(), nullable=False)
    hostname: Mapped[str] = mapped_column(db.String(), nullable=False)
    port: Mapped[str] = mapped_column(db.String(), nullable=False)
    api_key: Mapped[str] = mapped_column(db.String(), nullable=True)
    scans: Mapped[list['Scan']] = relationship('Scan', back_populates='node', foreign_keys='Scan.node_id', lazy='dynamic')

    @property
    def has_key(self):
        if self.api_key:
            return True
        return False

    @property
    def url(self):
        burp = BurpProApi(
            protocol=self.protocol,
            hostname=self.hostname,
            port=self.port,
            api_key=self.api_key,
        )
        return burp.url

    @property
    def is_alive(self):
        burp = BurpProApi(
            protocol=self.protocol,
            hostname=self.hostname,
            port=self.port,
            api_key=self.api_key,
        )
        return burp.is_alive()

    @property
    def active_scans(self):
        return [s for s in self.scans if s.status not in ['succeeded']]

    @staticmethod
    def get_live_nodes():
        live_nodes = []
        for node in Node.query.all():
            if node.is_alive:
                live_nodes.append(node)
        return live_nodes

    def __repr__(self):
        return f"<Node '{self.name}'>"
