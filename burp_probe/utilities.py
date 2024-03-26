from datetime import datetime, timezone, timedelta
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

    def __init__(self, scan):
        self.scan = scan
        self.result = self.scan.result_as_json

    def _log(self, s):
        print(f"[Burp Scan Parser] {s}")

    @property
    def status(self):
        return self.result['scan_status']

    @property
    def raw_start_time(self):
        return get_local_from_utc(self.scan.created)

    @property
    def raw_end_time(self):
        elapsed = self.result['scan_metrics']['total_elapsed_time']
        return get_local_from_utc(self.scan.created) + timedelta(seconds=elapsed)

    @property
    def raw_duration(self):
        return self.raw_end_time - self.raw_start_time

    @property
    def start_time(self):
        return f"{humanize.naturaldate(self.raw_start_time)} at {self.raw_start_time.strftime(self.time_format)}"

    @property
    def end_time(self):
        return f"{humanize.naturaldate(self.raw_end_time)} at {self.raw_end_time.strftime(self.time_format)}"

    @property
    def duration(self):
        return humanize.precisedelta(self.raw_duration, minimum_unit="seconds")





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
