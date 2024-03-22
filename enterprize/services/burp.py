import requests


class BurpProApi:

    def __init__(self, protocol='http', hostname='127.0.0.1', port=1337, api_key=None, version='0.1'):
        self.hostname = hostname
        self.port = port
        self.protocol = protocol
        self.version = version
        self.api_key = api_key
        if self.api_key:
            self.url = f"{protocol}://{hostname}:{port}/{api_key}/v{version}/"
        else:
            self.url = f"{protocol}://{hostname}:{port}/v{version}/"

    def _log(self, s):
        print(f"[Burp Service] {s}")

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
            self._log(f"{payload.get('type', 'HTTPError')}: {payload['error']}")
            raise
        except requests.exceptions.RequestException as e:
            self._log(f"Error: {e}")
            raise

    def post_scan_config(self, payload):
        response = self._call_api('/scan', 'POST', payload)
        data = {'task_id': int(response.headers.get('location', '-1'))}
        self._log('POST Scan Task Result:\n', json.dumps(data, indent=4))
        return data

    def get_scan_task(self, task_id):
        response = self._call_api(f'/scan/{task_id}', 'GET')
        data = response.json()
        self._log(f'GET Scan Task ({task_id}) Result\n', json.dumps(data, indent=4))
        return data

    def get_issue_definitions(self):
        response = self._call_api('/knowledge_base/issue_definitions', 'GET')
        data = response.json()
        self._log('GET Issue Definitions Result\n', json.dumps(data, indent=4))
        return data

    def is_alive(self):
        try:
            self._log(f"Burp API URL: {self.url}")
            response = requests.get(self.url)
            response.raise_for_status()
            return True
        except requests.exceptions.RequestException as e:
            self._log(f"Burp Node Test Failure: {e}")
            return False
