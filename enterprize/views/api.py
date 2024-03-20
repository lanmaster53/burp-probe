# api/views.py
from flask import request, current_app
from flask.views import MethodView
from flask_smorest import Blueprint
from enterprize.schemas import ConfigSchema, ScanSchema
from enterprize.services.burp import BurpProApi
import json

blp = Blueprint('api', __name__)

'''
@blp.route('/knowledge_base/issue_definitions')
class IssueDefinitionsList(MethodView):
    @blp.response(200)#, IssueDefinitionSchema(many=True))
    def get(self):
        return get_issue_definitions()
'''

@blp.route('/scans')
class ScanTasksList(MethodView):
    '''
    @blp.response(200)#, ScanSchema(many=True))
    def get(self):
        # Replace this with your actual logic to return HTML partials for HTMX request
        return []
    '''

    @blp.arguments(ConfigSchema, location='json')
    @blp.response(201)
    def post(self, scan_config):
        # Replace this with your actual logic to process the POST data
        burp = BurpProApi()
        return burp.post_scan_config(scan_config)

@blp.route('/scans/<int:task_id>')
class ScanTasksInst(MethodView):
    @blp.response(200, ScanSchema)
    def get(self, task_id):
        # Replace this with your actual logic to fetch data based on task_id
        burp = BurpProApi()
        return burp.get_scan_task(task_id)

@blp.route('/scans/callback', endpoint='callback')
class ScanTasksList(MethodView):
    @blp.arguments(ScanSchema, location='json')
    @blp.response(204)
    def put(self, payload):
        # Replace this with your actual logic to process the PUT data
        if payload['scan_status'] == 'succeeded':
            # store stuff as needed
            # is there a way to delete scans?
            pass
        current_app.logger.debug(f"Callback Payload:\n{json.dumps(payload, indent=4)}")
