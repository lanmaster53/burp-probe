from datetime import datetime, timezone, timedelta
import base64
import html
import humanize
import uuid

def get_current_utc_time():
    return datetime.now(timezone.utc)

def get_local_from_utc(dtg):
    return dtg.replace(tzinfo=timezone.utc).astimezone(tz=None)

def get_guid():
    return str(uuid.uuid4())


class BurpScanParser:

    dtg_format = "%Y-%m-%d %H:%M:%S"
    time_format = '%-I:%M %p'
    severity_weight = {'high': 4, 'medium': 3, 'low': 2, 'info': 1}

    def __init__(self, scan):
        self.scan = scan
        self.result = scan.result_as_json
        self.config = scan.config_as_json

    def _log(self, s):
        print(f"[Burp Scan Parser] {s}")

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
        print(f"*************** Unidentified evidence type: {evidence['type']}")
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
        parsed_request = ''
        for segment in segments:
            if segment['type'] == 'DataSegment':
                parsed_request += self.decode_segment_data(segment['data'])
            elif segment['type'] == 'HighlightSegment':
                parsed_request += f"<span style='background-color: orange;'>{self.decode_segment_data(segment['data'])}</span>"
            elif segment['type'] == 'SnipSegment':
                parsed_request += '\n\n**snipped**\n\n'
            else:
                print(f"*************** Unidentified request segment type: {segment['type']}")
        return parsed_request

    def codify(self, s):
        return f"<pre><code>{s}</code></pre>"

    def decode_segment_data(self, data):
        return html.escape(base64.b64decode(data).decode())


def burp_scan_builder(callback_url, credentials, configurations, scope_includes, scope_excludes, target_urls):
    scan_config = {}
    if callback_url:
        scan_config['scan_callback'] = {
            'url': callback_url,
        }
    if credentials:
        scan_config['application_logins'] = []
        for credential in credentials.split('\n'):
            username, password = [w.strip() for w in credential.split(':')]
            c = {
                'password': password,
                'type': 'UsernameAndPasswordLogin',
                'username': username,
            }
            scan_config['application_logins'].append(c)
    if configurations:
        scan_config['scan_configurations'] = []
        for configuration in configurations.split('\n'):
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
            for scope_include in scope_includes.split('\n'):
                c = {
                    'rule': scope_include
                }
                scan_config['scope']['include'].append(c)
        if scope_excludes:
            scan_config['scope']['exclude'] = []
            for scope_exclude in scope_excludes.split('\n'):
                c = {
                    'rule': scope_exclude
                }
                scan_config['scope']['exclude'].append(c)
    if target_urls:
        scan_config['urls'] = []
        for target_url in target_urls.split('\n'):
            scan_config['urls'].append(target_url)
    return scan_config
