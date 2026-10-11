#!/usr/bin/env python3
"""Smoke-test a packaged image using an isolated, labelled local container."""
import argparse
import json
import pathlib
import subprocess
import time
import urllib.error
import urllib.request
import uuid


def verify(image, version, engine):
    name = 'cloudreve-image-smoke-' + uuid.uuid4().hex[:12]
    subprocess.run([
        engine, 'run', '--detach', '--name', name,
        '--label', 'io.cloudreve.workspace=' + str(pathlib.Path.cwd()),
        '--publish', '127.0.0.1::5212', image,
    ], check=True)
    try:
        address = subprocess.check_output([engine, 'port', name, '5212/tcp'], text=True).strip()
        if not address.startswith('127.0.0.1:') or '\n' in address:
            raise SystemExit('Expected one loopback-only test port')
        base = 'http://' + address
        deadline = time.monotonic() + 120
        while True:
            try:
                with urllib.request.urlopen(base + '/api/v4/site/ping', timeout=3) as response:
                    ping = json.load(response)
                break
            except (urllib.error.URLError, TimeoutError, json.JSONDecodeError):
                if time.monotonic() >= deadline:
                    raise SystemExit('Packaged application did not become ready within 120 seconds')
                time.sleep(1)
        if ping.get('code') != 0 or ping.get('data') != version:
            raise SystemExit('Packaged backend version does not match the release tag')
        with urllib.request.urlopen(base + '/version.json', timeout=5) as response:
            frontend = json.load(response)
        if frontend.get('version') != version or frontend.get('name') != 'cloudreve-frontend':
            raise SystemExit('Packaged community frontend does not match the release tag')
        with urllib.request.urlopen(base + '/', timeout=5) as response:
            if b'<html' not in response.read().lower():
                raise SystemExit('Packaged frontend entry page is missing')
        print('Image startup and embedded frontend/backend versions verified')
    finally:
        subprocess.run([engine, 'stop', name], check=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--image', required=True)
    parser.add_argument('--version', required=True)
    parser.add_argument('--engine', choices=['docker', 'podman'], default='docker')
    args = parser.parse_args()
    verify(args.image, args.version, args.engine)
