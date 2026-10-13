#!/usr/bin/env python3
"""Serve the production bundle on loopback for deterministic browser regressions."""
import argparse
import functools
import http.server
import http.client
import json
import pathlib
import os
import urllib.parse

parser = argparse.ArgumentParser()
parser.add_argument('--port', type=int, default=43181)
args = parser.parse_args()
build = pathlib.Path(os.environ.get('CLOUDREVE_FRONTEND_BUILD', pathlib.Path(__file__).resolve().parents[1] / 'assets/build'))
if not (build / 'index.html').is_file():
    raise SystemExit('Build the production frontend before browser verification')

backend = None
if os.environ.get('CLOUDREVE_STORAGE_BROWSER_CONFIG'):
    config = json.loads(pathlib.Path(os.environ['CLOUDREVE_STORAGE_BROWSER_CONFIG']).read_text())
    backend = urllib.parse.urlsplit(config['backend'])
    if backend.scheme != 'http' or backend.hostname != '127.0.0.1':
        raise SystemExit('Native storage fixture backend must be owned loopback HTTP')


class SPA(http.server.SimpleHTTPRequestHandler):
    def proxy_native(self):
        if backend is None or not self.path.startswith(('/api/', '/f/')):
            return False
        body = self.rfile.read(int(self.headers.get('Content-Length', '0')))
        headers = {k: v for k, v in self.headers.items() if k.lower() not in ('host', 'connection', 'transfer-encoding')}
        connection = http.client.HTTPConnection(backend.hostname, backend.port, timeout=120)
        try:
            connection.request(self.command, self.path, body=body, headers=headers)
            response = connection.getresponse()
            raw = response.read()
            self.send_response(response.status)
            for key, value in response.getheaders():
                if key.lower() not in ('connection', 'transfer-encoding', 'content-length'):
                    self.send_header(key, value)
            self.send_header('Content-Length', str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)
        except (BrokenPipeError, ConnectionResetError):
            # Navigation can abandon an otherwise successful native response.
            pass
        finally:
            connection.close()
        return True

    def do_POST(self):
        if not self.proxy_native(): self.send_error(404)

    do_PUT = do_POST
    do_PATCH = do_POST
    do_DELETE = do_POST

    def do_GET(self):
        if self.proxy_native(): return
        path = urllib.parse.urlsplit(self.path).path
        if not pathlib.Path(self.translate_path(path)).is_file() and not path.startswith('/api/'):
            self.path = '/index.html'
        super().do_GET()

    def log_message(self, format, *args):
        pass


server = http.server.ThreadingHTTPServer(('127.0.0.1', args.port), functools.partial(SPA, directory=str(build)))
try:
    server.serve_forever()
except KeyboardInterrupt:
    pass
finally:
    server.server_close()
