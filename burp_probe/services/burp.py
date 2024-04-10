from burp_probe.utilities import get_local_from_utc
from datetime import timedelta
import base64
import html
import humanize
import json
import logging
import requests


class BurpServiceException(Exception):
    pass


class BurpProApi:

    def __init__(self, protocol='http', hostname='127.0.0.1', port=1337, api_key=None, version='0.1'):
        self.logger = logging.getLogger('burp_probe.burp_service')
        self.hostname = hostname
        self.port = port
        self.protocol = protocol
        self.version = version
        self.api_key = api_key
        if self.api_key:
            self.url = f"{protocol}://{hostname}:{port}/{api_key}/v{version}/"
        else:
            self.url = f"{protocol}://{hostname}:{port}/v{version}/"

    def _call_api(self, endpoint, method, data=None):
        headers = {'Content-Type': 'application/json'}
        try:
            url = '/'.join([self.url.rstrip('/'), endpoint.lstrip('/')])
            if method == 'POST':
                response = requests.post(url, headers=headers, json=data)
            elif method == 'GET':
                response = requests.get(url)
            else:
                raise ValueError(f"Unsupported HTTP method: {method}")
            response.raise_for_status()
            return response
        except requests.exceptions.HTTPError as e:
            payload = e.response.json()
            self.logger.debug(f"{payload.get('type', 'HTTPError')}: {payload['error']}")
            raise BurpServiceException(payload['error']) from e
        except requests.exceptions.RequestException as e:
            self.logger.debug(f"Error: {e}")
            raise BurpServiceException(str(e)) from e

    def post_scan_config(self, payload):
        response = self._call_api('/scan', 'POST', payload)
        data = {'task_id': int(response.headers.get('location', '-1'))}
        self.logger.debug(f"POST Scan Task Result:\n{json.dumps(data, indent=4)}")
        return data

    def get_scan_task(self, task_id):
        response = self._call_api(f'/scan/{task_id}', 'GET')
        data = response.json()
        self.logger.debug(f"GET Scan Task ({task_id}) Result:\n{json.dumps(data, indent=4)}")
        return data

    def get_issue_definitions(self):
        response = self._call_api('/knowledge_base/issue_definitions', 'GET')
        data = response.json()
        self.logger.debug(f"GET Issue Definitions Result:\n{json.dumps(data, indent=4)}")
        return data

    def is_alive(self):
        try:
            self.logger.debug(f"Burp API URL: {self.url}")
            response = requests.get(self.url)
            response.raise_for_status()
            return True
        except requests.exceptions.RequestException as e:
            self.logger.debug(f"Burp Node Test Failure: {e}")
            return False


class BurpScanBuilder:

    def __init__(self, callback_url, credentials, configurations, scope_includes, scope_excludes, target_urls):
        self.raw_callback_url = callback_url
        self.raw_credentials = credentials
        self.raw_configurations = configurations
        self.raw_scope_includes = scope_includes
        self.raw_scope_excludes = scope_excludes
        self.raw_target_urls = target_urls

    @property
    def callback_url(self):
        callback_url = {
            'url': self.raw_callback_url,
        }
        return callback_url

    @property
    def credentials(self):
        credentials = []
        for credential in self.raw_credentials.split('\n'):
            username, password = [w.strip() for w in credential.split(':', 1)]
            c = {
                'password': password,
                'type': 'UsernameAndPasswordLogin',
                'username': username,
            }
            credentials.append(c)
        return credentials

    @property
    def configurations(self):
        configurations = []
        for configuration in self.raw_configurations.split('\n'):
            c = {
                'name': configuration,
                'type': 'NamedConfiguration'
            }
            configurations.append(c)
        return configurations

    @property
    def scope_includes(self):
        scope_includes = []
        for scope_include in self.raw_scope_includes.split('\n'):
            c = {
                'rule': scope_include
            }
            scope_includes.append(c)
        return scope_includes

    @property
    def scope_excludes(self):
        scope_excludes = []
        for scope_exclude in self.raw_scope_excludes.split('\n'):
            c = {
                'rule': scope_exclude
            }
            scope_excludes.append(c)
        return scope_excludes

    @property
    def scope(self):
        scope = {}
        if self.raw_scope_includes:
            scope['include'] = self.scope_includes
        if self.raw_scope_excludes:
            scope['exclude'] = self.scope_excludes
        if scope:
            scope['type'] = 'SimpleScope'
        return scope

    @property
    def target_urls(self):
        target_urls = []
        for target_url in self.raw_target_urls.split('\n'):
            target_urls.append(target_url)
        return target_urls

    @property
    def config_as_json(self):
        scan_config = {}
        if self.raw_callback_url:
            scan_config['scan_callback'] = self.callback_url
        if self.raw_credentials:
            scan_config['application_logins'] = self.credentials
        if self.raw_configurations:
            scan_config['scan_configurations'] = self.configurations
        if self.raw_scope_includes or self.raw_scope_excludes:
            scan_config['scope'] = self.scope
        if self.raw_target_urls:
            scan_config['urls'] = self.target_urls
        return scan_config


class BurpScanParser:

    dtg_format = "%Y-%m-%d %H:%M:%S"
    time_format = '%-I:%M %p'
    severity_weight = {'high': 4, 'medium': 3, 'low': 2, 'info': 1}

    def __init__(self, scan):
        self.scan = scan
        self.result = scan.result_as_json
        self.config = scan.config_as_json

    @property
    def raw_start_time(self):
        return get_local_from_utc(self.scan.created)

    @property
    def raw_end_time(self):
        if not self.result:
            return self.raw_start_time
        elapsed = self.result['scan_metrics']['total_elapsed_time']
        return get_local_from_utc(self.scan.created) + timedelta(seconds=elapsed)

    @property
    def raw_duration(self):
        return self.raw_end_time - self.raw_start_time

    @property
    def start_time(self):
        return f"{humanize.naturaldate(self.raw_start_time)}, at {self.raw_start_time.strftime(self.time_format)}"

    @property
    def end_time(self):
        if not self.scan.is_dead:
            return self.scan.status
        return f"{humanize.naturaldate(self.raw_end_time)}, at {self.raw_end_time.strftime(self.time_format)}"

    @property
    def duration(self):
        return humanize.precisedelta(self.raw_duration, minimum_unit="seconds")

    @property
    def issue_count(self):
        if not self.result:
            return 0
        return self.result['scan_metrics']['issue_events']

    @property
    def issue_events(self):
        if not self.result:
            return []
        return self.result['issue_events']

    @property
    def organized_issue_events(self):
        sorted_issue_events = sorted(self.issue_events, key=lambda x: self.severity_weight[x['issue']['severity']], reverse=True)
        return self.organize_issue_events_by_type(sorted_issue_events)

    def organize_issue_events_by_type(self, issue_events):
        organized_issue_events = []
        for issue_event in issue_events:
            organized_issue_event = next((s for s in organized_issue_events if s['type_index'] == issue_event['issue']['type_index']), None)
            if not organized_issue_event:
                organized_issue_event = {'type_index': issue_event['issue']['type_index'], 'issue_events': []}
                organized_issue_events.append(organized_issue_event)
            organized_issue_event['issue_events'].append(issue_event)
        return organized_issue_events

    def organize_issue_events_by_severity(self, issue_events):
        organized_issue_events = []
        for issue_event in issue_events:
            organized_issue_event = next((s for s in organized_issue_events if s['severity'] == issue_event['issue']['severity']), None)
            if not organized_issue_event:
                organized_issue_event = {'severity': issue_event['issue']['severity'], 'issue_events': []}
                organized_issue_events.append(organized_issue_event)
            organized_issue_event['issue_events'].append(issue_event)
        return organized_issue_events

    @property
    def issues_by_severity(self):
        issues = {'high': [], 'medium': [], 'low': [], 'info': []}
        for issue in self.issue_events:
            issues[issue['issue']['severity']].append(issue)
        return issues


class BurpIssueParser:

    def __init__(self, issue_event):
        self.logger = logging.getLogger('burp_probe.burp_issue_parser')
        self.issue_event = issue_event

    @property
    def exhibits(self):
        exhibits = []
        for evidence in self.issue_event['issue']['evidence']:
            exhibits.extend(self.process_evidence(evidence))
        return exhibits

    def process_evidence(self, evidence):
        func = getattr(self, f"process_{evidence['type']}", None)
        if func:
            return func(evidence)
        self.logger.debug(f"Unidentified evidence type: {evidence['type']}")
        return []

    def process_FirstOrderEvidence(self, evidence):
        return self.process_message(evidence['request_response'])

    def process_DiffableEvidence(self, evidence):
        exhibits = []
        for instance in ['first_evidence', 'second_evidence']:
            exhibits.extend(self.process_evidence(evidence[instance]))
        return exhibits

    def process_TimingBasedEvidence(self, evidence):
        return self.process_evidence(evidence['evidence'])

    def process_InformationListEvidence(self, evidence):
        return self.process_message(evidence['request_response'])

    def process_CollaboratorEvidence(self, evidence):
        exhibits = []
        exhibits.extend(self.process_message(evidence['request_response']))
        if http_event := evidence.get('http_event'):
            exhibits.append({'title': f"Collaborator HTTP Interaction", 'content': http_event['description']})
            for exhibit in self.process_message(http_event['request_response']):
                exhibit['title'] = f"{exhibit['title']} (Collaborator)"
                exhibits.append(exhibit)
        if dns_event := evidence.get('dns_event'):
            exhibits.append({'title': f"Collaborator DNS Interaction", 'content': dns_event['description']})
        # have never seen a `smtp` event, so this will likely need to be updated at some point to include more detail
        if smtp_event := evidence.get('smtp_event'):
            exhibits.append({'title': f"Collaborator SMTP Interaction", 'content': smtp_event['description']})
        return exhibits

    def process_StoredEvidence(self, evidence):
        exhibits = []
        for exhibit in self.process_message(evidence['originating_request_response']):
            exhibit['title'] = f"{exhibit['title']} (Injection)"
            exhibits.append(exhibit)
        for exhibit in self.process_message(evidence['retrieval_request_response']):
            exhibit['title'] = f"{exhibit['title']} (Retrieval)"
            exhibits.append(exhibit)
        return exhibits

    def process_DynamicJavascriptAnalysisEvidence(self, evidence):
        exhibits = []
        exhibits.extend(self.process_evidence(evidence['composable_evidence']))
        content = ''
        if value := evidence.get('source_caption'):
            content += f"<p>Source:</p>\n{self.codify(html.escape(value))}"
        if value := evidence.get('sink_caption'):
            content += f"<p>Sink:</p>\n{self.codify(html.escape(value))}"
        if value := evidence.get('source_stack_trace'):
            content += f"<p>Source Stack Trace:</p>\n{self.codify(html.escape(value))}"
        if value := evidence.get('sink_stack_trace'):
            content += f"<p>Sink Stack Trace:</p>\n{self.codify(html.escape(value))}"
        if value := evidence.get('event_listener_stack_trace'):
            content += f"<p>Event Listener Stack Trace:</p>\n{self.codify(html.escape(value))}"
        if value := evidence.get('source_value'):
            content += f"<p>Source Value:</p>\n{self.codify(html.escape(value))}"
        if value := evidence.get('sink_value'):
            content += f"<p>Sink Value:</p>\n{self.codify(html.escape(value))}"
        if value := evidence.get('origin'):
            content += f"<p>Origin:</p>\n{self.codify(html.escape(value))}"
        if value := evidence.get('origin_checked'):
            content += f"<p>Origin Checked:</p>\n{self.codify(html.escape(value))}"
        if value := evidence.get('event_handler_data'):
            content += f"<p>Event Handler Data:</p>\n{self.codify(html.escape(value))}"
        if value := evidence.get('event_handler_data_type'):
            content += f"<p>Event Handler Data_type:</p>\n{self.codify(html.escape(value))}"
        if value := evidence.get('event_handler_modified_data'):
            content += f"<p>Event Handler Modified_data:</p>\n{self.codify(html.escape(value))}"
        if value := evidence.get('source_element_id'):
            content += f"<p>Source Element ID:</p>\n{self.codify(html.escape(value))}"
        if value := evidence.get('source_element_name'):
            content += f"<p>Source Element Name:</p>\n{self.codify(html.escape(value))}"
        if value := evidence.get('event_fired_event_name'):
            content += f"<p>Event Fired Name:</p>\n{self.codify(html.escape(value))}"
        if value := evidence.get('event_fired_element_id'):
            content += f"<p>Event Fired Element ID:</p>\n{self.codify(html.escape(value))}"
        if value := evidence.get('event_fired_element_name'):
            content += f"<p>Event Fired Element Name:</p>\n{self.codify(html.escape(value))}"
        if value := evidence.get('event_fired_outer_html'):
            content += f"<p>Event Fired HTML:</p>\n{self.codify(html.escape(value))}"
        exhibits.append({'title': f"Dynamic Analysis", 'content': content})
        return exhibits

    def process_message(self, message):
        exhibits = []
        request_segments = message['request']
        exhibits.append({'title': f"Request", 'content': self.codify(self.process_segments(request_segments))})
        response_segments = message['response']
        exhibits.append({'title': f"Response", 'content': self.codify(self.process_segments(response_segments))})
        return exhibits

    def process_segments(self, segments):
        content = ''
        for segment in segments:
            if segment['type'] == 'DataSegment':
                content += self.decode_segment_data(segment['data'])
            elif segment['type'] == 'HighlightSegment':
                content += f"<span style='background-color: orange;'>{self.decode_segment_data(segment['data'])}</span>"
            elif segment['type'] == 'SnipSegment':
                content += '\n\n**snipped**\n\n'
            else:
                self.logger.debug(f"Unidentified request segment type: {segment['type']}")
        return content

    def codify(self, s):
        return f"<pre><code>{s}</code></pre>"

    def decode_segment_data(self, data):
        return html.escape(base64.b64decode(data).decode())
