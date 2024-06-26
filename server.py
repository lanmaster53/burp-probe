#!/usr/bin/env python

from burp_probe import create_app
import os

app = create_app(os.environ.get('CONFIG', 'Development'))
if __name__ == '__main__':
    app.run(host='0.0.0.0')
