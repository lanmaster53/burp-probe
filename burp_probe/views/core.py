from flask import Blueprint, current_app, request, redirect, url_for, flash, render_template, abort
from burp_probe import db
from burp_probe.constants import ScanStates
from burp_probe.decorators import hx_trigger, login_required
from burp_probe.helpers import render_partial
from burp_probe.middleware import load_user, strip_empty_params, modify_response
from burp_probe.models import Node, Scan
from burp_probe.services.burp import BurpProApi, BurpServiceException
from burp_probe.utilities import burp_scan_builder, BurpIssueParser
from burp_probe.schemas import node_form_create_schema, node_form_update_schema, scan_form_schema
import json
import traceback

blp = Blueprint('core', __name__)

@blp.before_app_request
def call_request_middleware():
    load_user()
    strip_empty_params()

@blp.after_app_request
def call_response_middleware(response):
    response = modify_response(response)
    return response

@blp.route('/')
def index():
    return redirect(url_for('core.home'))

@blp.route('/home')
@login_required
def home():
    return redirect(url_for('core.scans'))

# region assets

@blp.route('/assets')
@login_required
def assets():
    return render_template(
        'pages/assets.html',
        assets=Scan.get_assets(),
    )

@blp.route('/assets/table')
@login_required
def assets_table():
    return render_partial(
        'partials/tables/assets.html',
        assets=Scan.get_assets(),
    )

# endregion

# region nodes

@blp.route('/nodes')
@login_required
def nodes():
    return render_template(
        'pages/nodes.html',
        nodes=Node.query.all(),
    )

@blp.route('/nodes/table')
@login_required
def nodes_table():
    return render_partial(
        'partials/tables/nodes.html',
        nodes=Node.query.all(),
    )

@blp.route('/nodes/form')
@login_required
def nodes_form():
    form = {}
    if node_id := request.args.get('node_id'):
        if node := Node.query.get(node_id):
            form = node.serialize()
    return render_partial(
        'partials/forms/nodes.html',
        errors={},
        form=form,
    )

@blp.route('/nodes', methods=['POST'])
@login_required
@hx_trigger('watch-refresh-nodes')
def nodes_create():
    errors = node_form_create_schema.validate(request.form)
    if errors:
        return render_partial(
            'partials/forms/nodes.html',
            errors=errors,
            form=request.form,
        ), 400
    node = Node(
        name=request.form.get('name'),
        description=request.form.get('description'),
        protocol=request.form.get('protocol'),
        hostname=request.form.get('hostname'),
        port=request.form.get('port'),
        api_key=request.form.get('api_key'),
    )
    db.session.add(node)
    db.session.commit()
    flash('Node created.', 'success')
    return '', 201

@blp.route('/nodes/<string:node_id>', methods=['PATCH'])
@login_required
@hx_trigger('watch-refresh-nodes')
def nodes_update(node_id):
    request.form['id'] = node_id
    errors = node_form_update_schema.validate(request.form)
    if errors:
        return render_partial(
            'partials/forms/nodes.html',
            errors=errors,
            form=request.form,
        ), 400
    node = Node.query.get(node_id)
    node.name=request.form.get('name')
    node.description=request.form.get('description')
    node.protocol=request.form.get('protocol')
    node.hostname=request.form.get('hostname')
    node.port=request.form.get('port')
    node.api_key=request.form.get('api_key')
    db.session.commit()
    flash('Node updated.', 'success')
    return '', 201

@blp.route('/nodes/<string:node_id>', methods=['DELETE'])
@login_required
@hx_trigger('watch-refresh-nodes')
def nodes_delete(node_id):
    if not (node := Node.query.get(node_id)):
        abort(404, description='Node does not exist.')
    db.session.delete(node)
    db.session.commit()
    flash('Node deleted.', 'success')
    return '', 200

@blp.route('/nodes/<string:node_id>/test')
@login_required
@hx_trigger('watch-refresh-nodes')
def nodes_test(node_id):
    node = Node.query.get(node_id)
    if node.is_alive:
        flash('Node is available.', 'success')
    else:
        flash('Node is not available.', 'warning')
    return '', 200

# endregion

# region scans

@blp.route('/scans')
@login_required
def scans():
    return render_template(
        'pages/scans.html',
        scans=Scan.query.all(),
    )

@blp.route('/scans/table')
@login_required
def scans_table():
    return render_partial(
        'partials/tables/scans.html',
        scans=Scan.query.all(),
    )

@blp.route('/scans/form')
@login_required
def scans_form():
    return render_partial(
        'partials/forms/scans.html',
        nodes=Node.get_live_nodes(),
        errors={},
        form={},
    )

@blp.route('/scans', methods=['POST'])
@login_required
@hx_trigger('watch-refresh-scans')
def scans_create():
    errors = scan_form_schema.validate(request.form)
    if errors:
        return render_partial(
            'partials/forms/scans.html',
            nodes=Node.get_live_nodes(),
            errors=errors,
            form=request.form,
        ), 400
    name = request.form.get('name')
    description = request.form.get('description')
    credentials = request.form.get('credentials')
    configurations = request.form.get('configurations')
    scope_includes = request.form.get('scope_includes')
    scope_excludes = request.form.get('scope_excludes')
    target_urls = request.form.get('targets')
    node_id = request.form.get('node')
    node = Node.query.get(node_id)
    # build and run the scan
    scan = Scan(
        name=name,
        description=description,
        status='created',
        node=node,
    )
    db.session.add(scan)
    db.session.flush()
    callback_url = None
    scan_config = burp_scan_builder(callback_url, credentials, configurations, scope_includes, scope_excludes, target_urls)
    current_app.logger.debug(f"Scanner Config:\n{json.dumps(scan_config, indent=4)}")
    burp = BurpProApi(
        protocol=node.protocol,
        hostname=node.hostname,
        port=node.port,
        api_key=node.api_key,
    )
    try:
        response = burp.post_scan_config(scan_config)
    except BurpServiceException as e:
        return render_partial(
            'partials/forms/scans.html',
            nodes=Node.get_live_nodes(),
            errors={'_other': [str(e)]},
            form=request.form,
        ), 400
    scan.configuration = json.dumps(scan_config)
    scan.status = ScanStates.STARTED
    scan.task_id = response['task_id']
    db.session.commit()
    flash('Scan initialized.', 'success')
    return '', 201

# endregion

# region scan

@blp.route('/scans/<string:scan_id>')
@login_required
def scan(scan_id):
    if not (scan := Scan.query.get(scan_id)):
        abort(404, description='Scan does not exist.')
    return render_template(
        'pages/scan.html',
        scan=scan,
    )

@blp.route('/scans/<string:scan_id>/header')
@login_required
def scan_header(scan_id):
    if not (scan := Scan.query.get(scan_id)):
        abort(404, description='Scan does not exist.')
    return render_partial(
        'partials/headers/scan.html',
        scan=scan,
    )

@blp.route('/scans/<string:scan_id>', methods=['DELETE'])
@login_required
@hx_trigger('watch-refresh-scans')
def scans_delete(scan_id):
    if not (scan := Scan.query.get(scan_id)):
        abort(404, description='Scan does not exist.')
    db.session.delete(scan)
    db.session.commit()
    flash('Scan deleted.', 'success')
    return '', 200

# endregion

# region issues

@blp.route('/scans/<string:scan_id>/issues/table')
@login_required
def issues_table(scan_id):
    if not (scan := Scan.query.get(scan_id)):
        abort(404, description='Scan does not exist.')
    type_ids = [int(t) for t in request.args.get('type_ids', '').split(',') if t]
    return render_partial(
        'partials/tables/issues.html',
        scan=scan,
        type_ids=type_ids,
    )

# endregion

# region issue

@blp.route('/scans/<string:scan_id>/issues/<string:issue_id>')
@login_required
def issue(scan_id, issue_id):
    if not (scan := Scan.query.get(scan_id)):
        abort(404, description='Scan does not exist.')
    if not (issue_event := scan.get_issue_by_id(issue_id)):
        abort(404, description='Issue does not exist.')
    issue_event['parsed'] = BurpIssueParser(issue_event)
    return render_template(
        'pages/issue.html',
        issue_event=issue_event,
    )

# endregion

# region error handlers

from werkzeug.exceptions import HTTPException

@blp.app_errorhandler(HTTPException)
def error_handler(e):
    if 'HX-Request' in request.headers:
        message = e.description
        flash(message, 'error')
        return '', e.code
    else:
        return e

@blp.app_errorhandler(Exception)
def internal_server_error(e):
    if 'HX-Request' in request.headers:
        current_app.logger.error(traceback.format_exc())
        message = 'Internal server error.'
        flash(message, 'error')
        return '', 500
    else:
        return e

# endregion
