from flask import Blueprint, request, redirect, url_for, flash, render_template, abort
from enterprize import db
from enterprize.decorators import hx_trigger
from enterprize.helpers import render_partial
from enterprize.middleware import load_user, modify_response
from enterprize.models import Asset, Node, Scan
from enterprize.services.burp import BurpProApi
from enterprize.utilities import burp_scan_builder
import json

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
        assets=Asset.query.all()
    )

@blp.route('/assets/modal')
#@login_required
def assets_modal():
    return render_partial(
        'partials/modals/assets.html',
    )

@blp.route('/assets', methods=['POST'])
#@login_required
@hx_trigger('watch-refresh-assets')
def assets_create():
    asset = Asset(
        url=request.form.get('url'),
        description=request.form.get('description'),
    )
    db.session.add(asset)
    db.session.commit()
    flash('Asset created.', 'success')
    return ''

@blp.route('/assets/<string:asset_id>', methods=['DELETE'])
#@login_required
@hx_trigger('watch-refresh-assets')
def assets_delete(asset_id):
    asset = Asset.query.filter_by(id=asset_id).first()
    if not asset:
        abort(404)
    db.session.delete(asset)
    db.session.commit()
    flash('Asset deleted.', 'success')
    return ''

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
    return ''

@blp.route('/nodes/<string:node_id>', methods=['DELETE'])
#@login_required
@hx_trigger('watch-refresh-nodes')
def nodes_delete(node_id):
    node = Node.query.filter_by(id=node_id).first()
    if not node:
        abort(404)
    db.session.delete(node)
    db.session.commit()
    flash('Node deleted.', 'success')
    return ''

@blp.route('/nodes/<string:node_id>/test')
#@login_required
def nodes_test(node_id):
    node = Node.query.filter_by(id=node_id).first()
    if node.is_alive:
        flash('Node is available.', 'success')
    else:
        flash('Node is not available.', 'warning')
    return ''

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
        assets=Asset.query.all(),
        nodes=Node.get_live_nodes(),
    )

@blp.route('/scans', methods=['POST'])
#@login_required
@hx_trigger('watch-refresh-scans')
def scans_create():
    name = request.form.get('name')
    description = request.form.get('description')
    credentials = request.form.get('credentials')
    configurations = request.form.get('configurations')
    scope_includes = request.form.get('scope_includes')
    scope_excludes = request.form.get('scope_excludes')
    asset_ids = request.form.getlist('assets')
    node_id = request.form.get('node')
    # resolve asset IDs
    assets = []
    for asset_id in asset_ids:
        asset = Asset.query.filter_by(id=asset_id).first()
        assets.append(asset)
    if len(assets) != len(asset_ids):
        flash('Invalid asset ID(s).', 'error')
        return ''
    asset_urls = [a.url for a in assets]
    # resolve node ID
    node = Node.query.filter_by(id=node_id).first()
    if not node:
        flash('Invalid node ID.', 'error')
        return ''
    if not node.is_alive:
        flash('Scanner node is not available.', 'error')
        return ''
    # build and run the scan
    callback_url = url_for('api.callback', _external=True)
    scan_config = burp_scan_builder(callback_url, credentials, configurations, scope_includes, scope_excludes, asset_urls)
    print(json.dumps(scan_config, indent=4))
    burp = BurpProApi(
        protocol=node.protocol,
        hostname=node.hostname,
        port=node.port,
        api_key=node.api_key,
    )
    '''response = burp.post_scan_config(scan_config)
    print(json.dumps(response, indent=4))
    scan = Scan(
        name=name,
        description=description,
        configuration=scan_config,
        status='started',
        result=None,
        task_id=response.headers.get['location'],
        assets=assets,
        node=node,
    )
    db.session.add(scan)
    db.session.commit()
    flash('Scan created.', 'success')'''
    return ''

@blp.route('/scans/<string:scan_id>', methods=['DELETE'])
#@login_required
@hx_trigger('watch-refresh-scans')
def scans_delete(scan_id):
    scan = Scan.query.filter_by(id=scan_id).first()
    if not scan:
        abort(404)
    db.session.delete(scan)
    db.session.commit()
    flash('Scan deleted.', 'success')
    return ''

# endregion
