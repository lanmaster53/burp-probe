from flask import current_app
from burp_probe import scheduler, db
from burp_probe.models import Scan
from burp_probe.services.burp import BurpProApi
import json
import requests
import traceback

DEAD_STATES = ['failed', 'cancelled', 'succeeded']

@scheduler.task('interval', id='sync_scan', seconds=10, misfire_grace_time=900)
def scan_sync():
    with scheduler.app.app_context():
        scans = Scan.query.all()
        for scan in scans:
            if scan.status not in DEAD_STATES:
                current_app.logger.info(f"[Scan Sync Task] \"{scan.name}\" is alive. Synchronizing.")
                burp = BurpProApi(
                    protocol=scan.node.protocol,
                    hostname=scan.node.hostname,
                    port=scan.node.port,
                    api_key=scan.node.api_key,
                )
                try:
                    payload = burp.get_scan_task(scan.task_id)
                except requests.exceptions.RequestException as e:
                    current_app.logger.error(f"[Scan Sync Task] \"{scan.name}\" synchronization failed.")
                    raise
                # update the scan
                scan.result = json.dumps(payload)
                scan.status = payload.get('scan_status')
                db.session.commit()
        current_app.logger.debug('[Scan Sync Task] Scans synchronized.')
