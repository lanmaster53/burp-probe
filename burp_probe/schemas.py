from burp_probe.models import Node, Scan
from marshmallow import Schema, fields, pre_load, validate, validates, validates_schema, ValidationError

# region form validation schemas


class LoginFormSchema(Schema):
    email = fields.Str(required=True)
    password = fields.Str(required=True)


class NodeFormSchema(Schema):
    name = fields.Str(required=True)
    description = fields.Str()
    protocol = fields.Str(required=True, validate=validate.Regexp(r'^[Hh][Tt][Tt][Pp][Ss]?$') )
    hostname = fields.Str(required=True, validate=validate.Regexp(r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$|^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)+([A-Za-z]|[A-Za-z][A-Za-z0-9\-]*[A-Za-z0-9])$'))
    port = fields.Str(required=True, validate=validate.Regexp(r'^\d+$'))
    api_key = fields.Str(required=True, validate=validate.Regexp(r'^[a-zA-Z0-9]{32}$'))


class NodeFormCreateSchema(NodeFormSchema):

    @validates('name')
    def name_is_unique(self, value):
        if Node.query.filter_by(name=value).first():
            raise ValidationError('Field must contain a unique value.')


class NodeFormUpdateSchema(NodeFormSchema):
    id = fields.Str(required=True)

    @validates_schema
    def name_is_unique(self, data, **kwargs):
        node = Node.query.filter_by(name=data.get('name')).first()
        if node and node.id != data.get('id'):
            raise ValidationError('Field must contain a unique value.', field_name='name')


class ScanFormSchema(Schema):
    name = fields.Str(required=True)
    description = fields.Str()
    credentials = fields.Str(validate=validate.Regexp(r'[^:]:[^:]'))
    configurations = fields.Str()
    targets = fields.Str(required=True)
    scope_includes = fields.Str(required=True)
    scope_excludes = fields.Str()
    node = fields.Str(required=True)

    @validates('name')
    def name_is_unique(self, value):
        if Scan.query.filter_by(name=value).first():
            raise ValidationError('Field must contain a unique value.')

    @validates('node')
    def node_is_valid(self, value):
        if not Node.query.get(value):
            raise ValidationError('Field must contain a valid node ID.')

    @validates('node')
    def node_is_alive(self, value):
        if not Node.query.get(value).is_alive:
            raise ValidationError('Field must contain an available node.')


login_form_schema = LoginFormSchema()
node_form_create_schema = NodeFormCreateSchema()
node_form_update_schema = NodeFormUpdateSchema()
scan_form_schema = ScanFormSchema()

# endregion

# region scan configuration schema


class ScanConfigurationSchema(Schema):
    type = fields.Str(required=True) # always `NamedConfiguration` because that's all that is allowed
    name = fields.Str(required=True)


class ApplicationLoginSchema(Schema):
    type = fields.Str(required=True) # always going to be `UsernameAndPasswordLogin` for now
    username = fields.Str(required=True)
    password = fields.Str(required=True)


class ScopeIncludeSchema(Schema):
    rule = fields.Str(required=True)


class ScopeSchema(Schema):
    type = fields.Str(required=True) # always going to be `SimpleScope` for now
    include = fields.List(fields.Nested(ScopeIncludeSchema), required=True)
    exclude = fields.List(fields.Nested(ScopeIncludeSchema))


class ScanCallbackSchema(Schema):
    url = fields.Str(required=True)


class ConfigSchema(Schema):
    scan_configurations = fields.List(fields.Nested(ScanConfigurationSchema))
    application_logins = fields.List(fields.Nested(ApplicationLoginSchema))
    urls = fields.List(fields.Str(), required=True)
    scope = fields.Nested(ScopeSchema, required=True)
    scan_callback = fields.Nested(ScanCallbackSchema, required=True)


# endregion

# region scan result schema


class ScanMetricsSchema(Schema):
    current_url = fields.Str()
    crawl_requests_made = fields.Integer()
    crawl_network_errors = fields.Integer()
    crawl_unique_locations_visited = fields.Integer()
    crawl_requests_queued = fields.Integer()
    audit_queue_items_completed = fields.Integer()
    audit_queue_items_waiting = fields.Integer()
    audit_requests_made = fields.Integer()
    audit_network_errors = fields.Integer()
    issue_events = fields.Integer()
    crawl_and_audit_caption = fields.Str()
    crawl_and_audit_progress = fields.Integer()
    total_elapsed_time = fields.Integer()


class ScanSchema(Schema):
    type = fields.Str()
    scan_metrics = fields.Nested(ScanMetricsSchema)
    issue_events = fields.List(fields.Dict())
    task_id = fields.Str()
    scan_status = fields.Str()
    message = fields.Str()
    error_code = fields.Integer()


# endregion
