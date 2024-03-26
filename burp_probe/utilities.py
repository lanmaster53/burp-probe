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
