from burp_probe import db, bcrypt
from burp_probe.constants import ScanStates
from burp_probe.services.burp import BurpProApi
from burp_probe.utilities import get_guid, get_current_utc_time, get_local_from_utc, BurpScanParser
from sqlalchemy.orm import Mapped, mapped_column, relationship
import binascii
import json

# https://github.com/pallets-eco/flask-sqlalchemy/issues/1140


class BaseModel(db.Model):
    __abstract__ = True
    id: Mapped[str] = mapped_column(db.String(36), primary_key=True, default=get_guid)
    created: Mapped[str] = mapped_column(db.DateTime, nullable=False, default=get_current_utc_time)

    def attr_is_nullable(self, s):
        return self.__table__.columns[s].nullable


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

    @property
    def config_as_json(self):
        return json.loads(self.configuration) if self.configuration else {}

    @property
    def result_as_json(self):
        return json.loads(self.result) if self.result else {}

    @property
    def is_dead(self):
        return self.status in ScanStates.DEAD

    @property
    def is_finished(self):
        return self.status in ScanStates.FINISHED

    @property
    def is_error(self):
        return self.status in ScanStates.ERROR

    @property
    def is_active(self):
        return self.status in ScanStates.ACTIVE

    @property
    def parsed(self):
        return BurpScanParser(self)

    def get_issue_by_id(self, issue_id):
        return next((i for i in self.parsed.result['issue_events'] if i['id'] == issue_id), None)

    @staticmethod
    def get_assets():
        assets = []
        for scan in Scan.query.all():
            for url in scan.parsed.config['urls']:
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
    api_key: Mapped[str] = mapped_column(db.String(), nullable=False)
    scans: Mapped[list['Scan']] = relationship('Scan', back_populates='node', foreign_keys='Scan.node_id', lazy='dynamic')

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
        return [s for s in self.scans if s.is_active]

    @staticmethod
    def get_live_nodes():
        live_nodes = []
        for node in Node.query.all():
            if node.is_alive:
                live_nodes.append(node)
        return live_nodes

    def __repr__(self):
        return f"<Node '{self.name}'>"
