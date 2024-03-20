from flask import Blueprint, request, redirect, url_for, flash, render_template, abort
from enterprize import db
from enterprize.decorators import hx_trigger
from enterprize.helpers import render_partial
from enterprize.middleware import load_user, modify_response
from enterprize.models import Asset, Node, Scan
from enterprize.services.burp import BurpProApi

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
    return render_template('pages/assets.html', assets=Asset.query.all())

@blp.route('/assets/partial')
#@login_required
def assets_partial():
    return render_partial('partials/assets.html', assets=Asset.query.all())

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
    return render_template('pages/nodes.html', nodes=Node.query.all())

@blp.route('/nodes/partial')
#@login_required
def nodes_partial():
    return render_partial('partials/nodes.html', nodes=Node.query.all())

@blp.route('/nodes', methods=['POST'])
#@login_required
@hx_trigger('watch-refresh-nodes')
def nodes_create():
    node = Node(
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
        flash('Node is not available.', 'info')
    return ''

# endregion

# region scans





@blp.route('/scans')
#@login_required
def scans():
    return render_template('pages/scans.html', scans=Scan.query.all())

@blp.route('/scans/partial')
#@login_required
def scans_partial():
    return render_partial('partials/scans.html', scans=Scan.query.all())

@blp.route('/scans', methods=['POST'])
#@login_required
@hx_trigger('watch-refresh-scans')
def scans_create():
    credentials = request.form.get('credentials')
    configurations = request.form.get('configurations')
    scope_includes = request.form.get('scope_includes')
    scope_excludes = request.form.get('scope_excludes')
    asset_ids = request.form.get('assets')
    node_id = request.form.get('node')
    scan_config = {
        'scan_callback': {
            'url': url_for('api.callback', _external=True),
        }
    }
    if credentials:
        scan_config['application_logins'] = []
        for credential in [c.strip() for c in credentials.split(',')]:
            username, password = [w.strip() for w in credential.split(':')]
            c = {
                'password': password,
                'type': 'UsernameAndPasswordLogin',
                'username': username,
            }
            scan_config['application_logins'].append(c)
    if configurations:
        scan_config['scan_configurations'] = []
        for configuration in [c.strip() for c in configurations.split(',')]:
            c = {
                'name': configuration,
                'type': 'NamedConfiguration'
            }
            scan_config['scan_configurations'].append(c)
    if scope_includes or scope_excludes:
        scan_config['scope'] = {
            'type': 'SimpleScope',
        }
        if scope_includes:
            scan_config['scope']['include'] = []
            for scope_include in [c.strip() for c in scope_includes.split(',')]:
                c = {
                    'rule': scope_include
                }
                scan_config['scope']['include'].append(c)
        if scope_excludes:
            scan_config['scope']['exclude'] = []
            for scope_exclude in [c.strip() for c in scope_excludes.split(',')]:
                c = {
                    'rule': scope_exclude
                }
                scan_config['scope']['exclude'].append(c)
    if asset_ids:
        scan_config['urls'] = []
        for asset_id in [c.strip() for c in asset_ids.split(',')]:
            asset = Asset.query.filter_by(id=asset_id).first()
            scan_config['urls'].append(asset.url)
    # need to check that node is up
    import json
    print(json.dumps(scan_config, indent=4))
    node = Node.query.filter_by(id=node_id).first()
    burp = BurpProApi(
        protocol=node.protocol,
        hostname=node.hostname,
        port=node.port,
        api_key=node.api_key,
    )
    response = burp.post_scan_config(scan_config)
    print(json.dumps(response, indent=4))
    '''scan = Scan(
        description=request.form.get('description'),
    )
    db.session.add(scan)
    db.session.commit()'''
    flash('Scan created.', 'success')
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
