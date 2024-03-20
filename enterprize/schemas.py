# api/schemas.py
from marshmallow import Schema, fields

# scan configuration schema


class ScanConfigurationSchema(Schema):
    type = fields.Str(required=True) # always `NamedConfiguration` because that's all that is allowed
    name = fields.Str(required=True)


class ApplicationLoginSchema(Schema):
    type = fields.Str(required=True) # always going to be `UsernameAndPasswordLogin`` for now
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


# scan result schema


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
