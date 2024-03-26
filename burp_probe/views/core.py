from flask import Blueprint, current_app, request, redirect, url_for, flash, render_template, abort, Response
from burp_probe import db
from burp_probe.decorators import hx_trigger
from burp_probe.helpers import render_partial
from burp_probe.middleware import load_user, modify_response
from burp_probe.models import Node, Scan
from burp_probe.services.burp import BurpProApi
from burp_probe.utilities import burp_scan_builder, BurpScanParser
import json
import requests
import traceback

blp = Blueprint('core', __name__)

@blp.before_app_request
def call_request_middleware():
    load_user()

@blp.after_app_request
def call_response_middleware(response):
    response = modify_response(response)
    return response

@blp.route('/')
def index():
    return redirect(url_for('core.home'))

@blp.route('/home')
#@login_required
def home():
    return redirect(url_for('core.scans'))

# region assets

@blp.route('/assets')
#@login_required
def assets():
    return render_template(
        'pages/assets.html',
)

@blp.route('/assets/table')
#@login_required
def assets_table():
    return render_partial(
        'partials/tables/assets.html',
        assets=Scan.get_assets()
    )

# endregion

# region nodes

@blp.route('/nodes')
#@login_required
def nodes():
    return render_template(
        'pages/nodes.html',
    )

@blp.route('/nodes/table')
#@login_required
def nodes_table():
    return render_partial(
        'partials/tables/nodes.html',
        nodes=Node.query.all()
    )

@blp.route('/nodes/modal')
#@login_required
def nodes_modal():
    return render_partial(
        'partials/modals/nodes.html',
    )

@blp.route('/nodes', methods=['POST'])
#@login_required
@hx_trigger('watch-refresh-nodes')
def nodes_create():
    node = Node(
        name=request.form.get('name') or None,
        description=request.form.get('description') or None,
        protocol=request.form.get('protocol') or None,
        hostname=request.form.get('hostname') or None,
        port=request.form.get('port') or None,
        api_key=request.form.get('api_key') or None,
    )
    db.session.add(node)
    db.session.commit()
    flash('Node created.', 'success')
    return '', 201

@blp.route('/nodes/<string:node_id>', methods=['DELETE'])
#@login_required
@hx_trigger('watch-refresh-nodes')
def nodes_delete(node_id):
    node = Node.query.get(node_id)
    if not node:
        abort(404, description='Node does not exist.')
    db.session.delete(node)
    db.session.commit()
    flash('Node deleted.', 'success')
    return '', 200

@blp.route('/nodes/<string:node_id>/test')
#@login_required
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
#@login_required
def scans():
    return render_template(
        'pages/scans.html',
    )

@blp.route('/scans/table')
#@login_required
def scans_table():
    return render_partial(
        'partials/tables/scans.html',
        scans=Scan.query.all(),
    )

@blp.route('/scans/modal')
#@login_required
def scans_modal():
    return render_partial(
        'partials/modals/scans.html',
        nodes=Node.get_live_nodes(),
    )

@blp.route('/scans', methods=['POST'])
#@login_required
@hx_trigger('watch-refresh-scans')
def scans_create():
    name = request.form.get('name' or None)
    description = request.form.get('description' or None)
    credentials = request.form.get('credentials' or None)
    configurations = request.form.get('configurations' or None)
    scope_includes = request.form.get('scope_includes' or None)
    scope_excludes = request.form.get('scope_excludes' or None)
    target_urls = request.form.get('targets' or None)
    node_id = request.form.get('node' or None)
    # resolve node ID
    node = Node.query.get(node_id)
    if not node:
        abort(400, description='Invalid node ID.')
    if not node.is_alive:
        abort(404, description='Node is not available.')
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
    except requests.exceptions.RequestException as e:
        abort(500, description='Scan initialization failed.')
    scan.configuration = json.dumps(scan_config)
    scan.status = 'started'
    scan.task_id = response['task_id']
    db.session.commit()
    flash('Scan initialized.', 'success')
    return '', 201

@blp.route('/scans/<string:scan_id>/sync')
#@login_required
@hx_trigger('watch-refresh-scans')
def scans_sync(scan_id):
    scan = Scan.query.get(scan_id)
    if not scan:
        abort(404, description='Scan does not exist.')
    if not scan.node.is_alive:
        abort(404, description='Node is not available.')
    burp = BurpProApi(
        protocol=scan.node.protocol,
        hostname=scan.node.hostname,
        port=scan.node.port,
        api_key=scan.node.api_key,
    )
    try:
        payload = burp.get_scan_task(scan.task_id)
    except requests.exceptions.RequestException as e:
        abort(500, description='Scan synchronization failed.')
    current_app.logger.debug(f"Scan Sync Payload:\n{json.dumps(payload, indent=4)}")
    # update the scan
    scan.result = json.dumps(payload)
    scan.status = payload.get('scan_status')
    db.session.commit()
    flash('Scan synchronized.', 'success')
    return '', 200

@blp.route('/scans/<string:scan_id>')
#@login_required
def scan(scan_id):
    scan = Scan.query.get(scan_id)
    if not scan:
        abort(404, description='Scan does not exist.')
    parsed_scan = BurpScanParser(scan)
    #import pdb;pdb.set_trace()
    return render_template(
        'pages/scan.html',
        parsed_scan=parsed_scan,
    )

@blp.route('/scans/<string:scan_id>', methods=['DELETE'])
#@login_required
@hx_trigger('watch-refresh-scans')
def scans_delete(scan_id):
    scan = Scan.query.get(scan_id)
    if not scan:
        abort(404, description='Scan does not exist.')
    db.session.delete(scan)
    db.session.commit()
    flash('Scan deleted.', 'success')
    return '', 200

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
