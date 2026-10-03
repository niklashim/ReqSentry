#!/usr/bin/env python3
"""Run the real ReqSentry daemon against reproducible, synthetic log traffic.

Uses only Python's standard library. No public IP is contacted, no real user
records are used, and remote delivery is disabled. Generated data stays under
Git-ignored dev-data/. Country/ASN data and PHP-FPM status are fictional fixtures.
"""
import argparse
import datetime as dt
import ipaddress
import json
from pathlib import Path
import random
import signal
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.request import urlopen

REPO = Path(__file__).resolve().parents[1]
SITES = ['shop.example', 'api.example', 'docs.example', 'blog.example']
CLIENTS = []
for n in range(1, 41):
    CLIENTS.append({'ip': f'198.51.100.{n}', 'kind': 'browser', 'country': ['SE', 'GB', 'US', 'DE'][n % 4]})
for n in range(1, 9):
    CLIENTS.append({'ip': f'2001:db8::{n}', 'kind': 'browser', 'country': 'SE'})
for n in range(31, 43):
    CLIENTS.append({'ip': f'203.0.113.{n}', 'kind': ['scan', 'suspicious', 'watch', 'cost'][(n - 31) % 4], 'country': ['DE', 'GB', 'US', 'SE'][(n - 31) % 4]})


def control(kind, size):
    """Encode the bounded subset of the published MaxMind DB v2 format used here."""
    if size < 29:
        length, extra = size, b''
    elif size < 285:
        length, extra = 29, bytes([size - 29])
    else:
        length, extra = 30, (size - 285).to_bytes(2, 'big')
    return bytes([((kind if kind < 8 else 0) << 5) | length]) + (bytes([kind - 7]) if kind > 7 else b'') + extra


def encode(value):
    if isinstance(value, dict):
        return control(7, len(value)) + b''.join(encode(k) + encode(v) for k, v in value.items())
    if isinstance(value, list):
        return control(11, len(value)) + b''.join(encode(v) for v in value)
    if isinstance(value, (int, tuple)):
        kind, number = (6, value) if isinstance(value, int) else value
        payload = number.to_bytes(max(1, (number.bit_length() + 7) // 8), 'big')
        return control(kind, len(payload)) + payload
    payload = value.encode('utf-8')
    return control(2, len(payload)) + payload


def synthetic_mmdb(path):
    """Fictional metadata on reserved documentation IPs, read by real MMDB code.

    Format reference: https://maxmind.github.io/MaxMind-DB/
    This is not a downloaded or licensed MaxMind geolocation database.
    """
    nodes, records = [[None, None]], []
    countries = {'DE': 'Germany', 'GB': 'United Kingdom', 'US': 'United States', 'SE': 'Sweden'}
    for client in CLIENTS:
        hosting = client['kind'] != 'browser'
        country = client['country']
        record = {'country': {'iso_code': country}, 'traits': {
            'autonomous_system_number': 64512 + list(countries).index(country) + (4 if hosting else 0),
            'autonomous_system_organization': f'Example {"Hosting" if hosting else "Broadband"} {country}',
            'isp': f'Synthetic demo · {countries[country]}',
            'user_type': 'hosting' if hosting else 'residential'}}
        record_id = len(records)
        records.append(encode(record))
        address = int(ipaddress.ip_address(client['ip']))
        node = 0
        for shift in range(127, -1, -1):
            bit = (address >> shift) & 1
            if shift == 0:
                nodes[node][bit] = ('record', record_id)
            else:
                if nodes[node][bit] is None:
                    nodes[node][bit] = len(nodes)
                    nodes.append([None, None])
                node = nodes[node][bit]
    offsets, data = [], bytearray()
    for record in records:
        offsets.append(len(data))
        data.extend(record)
    tree = bytearray()
    for node in nodes:
        for pointer in node:
            value = len(nodes) if pointer is None else (len(nodes) + 16 + offsets[pointer[1]] if isinstance(pointer, tuple) else pointer)
            tree.extend(value.to_bytes(3, 'big'))
    metadata = {'node_count': len(nodes), 'record_size': (5, 24), 'ip_version': (5, 6),
                'database_type': 'ReqSentry-Synthetic-Demo', 'languages': ['en'],
                'binary_format_major_version': (5, 2), 'binary_format_minor_version': (5, 0),
                'build_epoch': (9, 1791028800), 'description': {'en': 'Fictional demo data; reserved IPs only; not production geolocation'}}
    path.write_bytes(tree + bytes(16) + data + b'\xab\xcd\xefMaxMind.com' + encode(metadata))


class PoolFixture(BaseHTTPRequestHandler):
    def do_GET(self):
        active = 5 + int(time.monotonic()) % 12
        payload = json.dumps({'pool': 'demo-pool', 'active processes': active, 'idle processes': 24-active,
                              'total processes': 24, 'max active processes': 22, 'max children reached': 0,
                              'slow requests': 3, 'listen queue': 0}).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *_):
        pass


def emit(files, tick, rng):
    now = dt.datetime.now(dt.timezone.utc)
    timestamp = now.isoformat(timespec='milliseconds').replace('+00:00', 'Z')
    for index, client in enumerate(CLIENTS):
        kind = client['kind']
        count = {'browser': 1 + (tick + index) % 2, 'scan': 6, 'suspicious': 3, 'watch': 11, 'cost': 4}[kind]
        # Vary the overall traffic curve without lowering detector thresholds.
        if kind == 'browser' and tick % 90 > 60:
            count += 1
        for j in range(count):
            sequence = tick * 100 + j
            site_index = ((index + tick // 30) % 4 if kind == 'browser'
                          else index % 4 if kind == 'suspicious' else (index + j) % 4)
            site = SITES[site_index]
            method, status, request_time = 'GET', 200, round(rng.uniform(.008, .085), 4)
            ua = 'Mozilla/5.0 (Demo Browser)'
            path, query = rng.choice(['/','/catalog','/about','/assets/app.js','/api/products']), ''
            if kind in ('scan', 'suspicious'):
                path = f'/wp-content/plugins/{sequence}/config.php'
                status, ua = 404, 'SyntheticScan/1.0'
                if kind == 'scan':
                    method = ['POST', 'PUT', 'DELETE'][j % 3]
            elif kind == 'watch':
                path, status, ua = '/missing-resource', 404, 'SyntheticMonitor/1.0'
            elif kind == 'cost':
                path, query, ua = '/api/export', f'id={sequence}', 'SyntheticClient/1.0'
                request_time, status = 1.25, (502 if j == 0 else 200)
            elif sequence % 41 == 0:
                path, status = '/old-catalog', 301
            elif sequence % 67 == 0:
                path, status = '/checkout', 503
            request_id = f'demo-{tick:06d}-{index:02d}-{j:02d}'
            event = {'timestamp': timestamp, 'client_ip': client['ip'], 'peer_ip': client['ip'], 'method': method,
                     'target': path + ('?' + query if query else ''), 'status': status, 'bytes': 640 if status>=400 else 4096,
                     'host': site, 'user_agent': ua, 'referrer': '-', 'request_time': request_time,
                     'upstream_time': round(request_time*.85,4), 'request_id': request_id, 'trace_id': f'trace-{request_id}'}
            if site_index == 0:
                line = f'{client["ip"]} - - [{now.strftime("%d/%b/%Y:%H:%M:%S +0000")}] "{method} {event["target"]} HTTP/1.1" {status} {event["bytes"]} "-" "{ua}" rt={request_time} urt={event["upstream_time"]} rid="{request_id}" trace="trace-{request_id}"'
            elif site_index == 1:
                line = json.dumps(event, separators=(',', ':'))
            elif site_index == 2:
                line = ' '.join(f'{key}={json.dumps(value)}' for key,value in event.items())
            else:
                line = json.dumps({'@timestamp': timestamp, 'client': {'ip': client['ip']}, 'source': {'ip': client['ip']},
                    'http': {'request': {'method': method, 'id': request_id}, 'response': {'status_code': status, 'body': {'bytes': event['bytes']}}},
                    'url': {'path': path, 'query': query, 'domain': site}, 'user_agent': {'original': ua},
                    'event': {'duration': int(request_time*1e9)}, 'trace': {'id': f'trace-{request_id}'}}, separators=(',', ':'))
            files[site].write(line+'\n')
            if kind == 'scan' and j == count-1 and tick % 3 == 0:
                error = {'timestamp': timestamp, 'client_ip': client['ip'], 'severity': 'error', 'message': 'Upstream connection refused during synthetic request',
                         'error_type': 'upstream_refused', 'path': path, 'request_id': request_id, 'trace_id': f'trace-{request_id}'}
                files['errors'].write(json.dumps(error | {'site': site})+'\n')
    for handle in files.values():
        handle.flush()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--duration', type=int, default=300, help='seconds to run (default: 300)')
    parser.add_argument('--port', type=int, default=18092)
    parser.add_argument('--listen', default='127.0.0.1', choices=['127.0.0.1', '0.0.0.0'], help='0.0.0.0 only for an isolated Docker demo')
    parser.add_argument('--data-dir', type=Path, default=REPO/'dev-data'/'demo')
    parser.add_argument('--binary', type=Path, help='existing ReqSentry binary; otherwise builds from this checkout')
    args = parser.parse_args()
    if args.duration < 30 or not 1 <= args.port <= 65535:
        parser.error('duration must be at least 30 seconds and port must be 1..65535')
    args.data_dir.mkdir(parents=True, exist_ok=True)
    run = args.data_dir.resolve()/('run-'+dt.datetime.now().strftime('%Y%m%d-%H%M%S')+'-'+str(time.time_ns()%1_000_000))
    run.mkdir(mode=0o700)
    binary = args.binary.resolve() if args.binary else args.data_dir.resolve()/'reqsentry'
    if not args.binary:
        subprocess.run(['go','build','-o',str(binary),'./cmd/reqsentry'],cwd=REPO,check=True)
    for folder in ['logs','maxmind','state']:
        (run/folder).mkdir(mode=0o700)
    synthetic_mmdb(run/'maxmind'/'GeoIP2-Enterprise.mmdb')
    sources = []
    for i, site in enumerate(SITES):
        path = run/'logs'/(site+'.access.log')
        path.touch(mode=0o600)
        sources.append({'path':str(path),'site':site,'format':['combined','json','logfmt','json'][i]} | ({'profile':'ecs'} if i==3 else {}))
    errors=[]
    # Each site gets a canonical JSON error source, so request-ID associations
    # are site-scoped. The emitter routes error fixtures to the matching file.
    for site in SITES:
        path=run/'logs'/(site+'.error.jsonl')
        path.touch(mode=0o600)
        errors.append({'path':str(path),'site':site,'format':'json','minimum_severity':'warning'})
    pool = ThreadingHTTPServer(('127.0.0.1',0), PoolFixture)
    threading.Thread(target=pool.serve_forever,daemon=True).start()
    cfg={'server':{'name':'demo-web-01'},'mode':'monitor','access_files':sources,'error_files':errors,
         'log_profiles':{'ecs':{'preset':'ecs-v1'}},'trigger':{'mode':'always'},'analysis':{'window':'30s'},
         'database':{'path':str(run/'state'/'reqsentry.db'),'retention':{'max_age':'96h'}},
         'maxmind':{'enabled':True,'database_dir':str(run/'maxmind'),'update':{'enabled':False}},
         'php_fpm':{'enabled':True,'interval':'2s','pools':[{'name':'demo-pool','status_url':f'http://127.0.0.1:{pool.server_port}/status?json'}]},
         'output':{'log':{'enabled':True,'path':str(run/'logs'/'reqsentry.log')},'incidents':{'enabled':True,'path':str(run/'logs'/'incidents.jsonl')}},
         'web':{'enabled':True,'listen':args.listen,'port':args.port,'allowed_ips':['127.0.0.1','::1']+(['172.16.0.0/12','192.168.65.0/24'] if args.listen=='0.0.0.0' else []),
                'realtime':{'enabled':True,'interval':'1s','max_clients':16}}}
    config_path=run/'config.yaml'
    config_path.write_text(json.dumps(cfg,indent=2)+'\n') # JSON is valid YAML.
    config_path.chmod(0o600)
    stop=threading.Event()
    for sig in (signal.SIGINT,signal.SIGTERM):
        signal.signal(sig, lambda *_: stop.set())
    diagnostics=(run/'logs'/'daemon.stderr.log').open('w')
    process=subprocess.Popen([str(binary),'-config',str(config_path)],stdout=diagnostics,stderr=diagnostics)
    handles={site:Path(sources[i]['path']).open('a') for i,site in enumerate(SITES)}
    error_handles={site:Path(errors[i]['path']).open('a') for i,site in enumerate(SITES)}
    class ErrorRouter:
        def write(self,line):
            event=json.loads(line)
            site=event.pop('site')
            error_handles[site].write(json.dumps(event)+'\n')
        def flush(self):
            for handle in error_handles.values(): handle.flush()
    handles['errors']=ErrorRouter()
    try:
        for _ in range(100):
            if process.poll() is not None:
                raise RuntimeError(f'Daemon exited; inspect {run}/logs/daemon.stderr.log')
            ready=(run/'logs'/'daemon.stderr.log').read_text().count('watching log source path=') >= len(sources)+len(errors)
            if ready:
                with urlopen(f'http://127.0.0.1:{args.port}/api/v1/status',timeout=2) as response:
                    if response.status==200: break
            stop.wait(.1)
        else:
            raise RuntimeError('Daemon startup timed out')
        print(f'Synthetic demo ready: http://127.0.0.1:{args.port}',flush=True)
        print(f'60 fictional clients · 4 sites · combined/JSON/logfmt/ECS · monitor only\nData: {run}\nWait 30 seconds for scores; 2 minutes for trend charts. Ctrl+C stops.',flush=True)
        rng=random.Random(20261003)
        started=time.monotonic()
        for tick in range(args.duration):
            if stop.is_set(): break
            if process.poll() is not None: raise RuntimeError('Daemon stopped during demo')
            emit(handles,tick,rng)
            stop.wait(max(0,started+tick+1-time.monotonic()))
    finally:
        for handle in [*handles.values(),*error_handles.values()]:
            if hasattr(handle,'close'): handle.close()
        process.terminate()
        try: process.wait(timeout=15)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
        pool.shutdown()
        pool.server_close()
        diagnostics.close()
        print(f'Demo stopped. Local history retained in {run}',flush=True)


if __name__=='__main__':
    main()
