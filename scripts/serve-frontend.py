#!/usr/bin/env python3
"""Serve the production bundle on loopback for deterministic browser regressions."""
import argparse
import functools
import http.server
import pathlib
import os
import urllib.parse

parser = argparse.ArgumentParser()
parser.add_argument('--port', type=int, default=43181)
args = parser.parse_args()
build = pathlib.Path(os.environ.get('CLOUDREVE_FRONTEND_BUILD', pathlib.Path(__file__).resolve().parents[1] / 'assets/build'))
if not (build / 'index.html').is_file():
    raise SystemExit('Build the production frontend before browser verification')


class SPA(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
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
