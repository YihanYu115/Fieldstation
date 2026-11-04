"""Local, read-only Fieldstation console. Credentials stay in the host environment."""
import json
import os
import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, urlencode, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

HERE = Path(__file__).resolve().parent
ROUTES = {
    'issue': ('im', '/v1/browse/issue', {'id'}),
    'children': ('im', '/v1/browse/children', {'id', 'cursor', 'expected_snapshot'}),
    'evidence': ('im', '/v1/browse/evidence', {'id', 'cursor', 'expected_snapshot'}),
    'detail': ('im', '/v1/browse/detail', {'id'}),
    'neighbors': ('im', '/v1/browse/neighbors', {'id', 'cursor', 'expected_snapshot'}),
    'conclusions': ('im', '/v1/browse/conclusions', {'id', 'cursor', 'expected_snapshot'}),
    'messages': ('board', '/v1/board/messages', {'issue_id', 'cursor'}),
    'handoffs': ('board', '/v1/board/handoffs', {'issue_id', 'cursor'}),
    'instructions': ('board', '/v1/board/instructions', {'issue_id', 'cursor'}),
    'tasks': ('queue', '/v1/queue/tasks', {'issue_id', 'cursor', 'claimed'}),
    'task': ('queue', '/v1/queue/tasks/{id}', {'id'}),
    'replies': ('queue', '/v1/queue/tasks/{id}/replies', {'id', 'cursor'}),
    'message': ('board', '/v1/board/messages/{id}', {'id'}),
    'handoff': ('board', '/v1/board/handoffs/{id}', {'id'}),
    'instruction': ('board', '/v1/board/instructions/{id}', {'id'}),
    'catalog': ('host', '/v1/catalog', set()),
}

class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None

def read_source(name, params):
    service, path, allowed = ROUTES[name]
    if set(params) - allowed or any(len(v) != 1 or len(v[0]) > 2048 for v in params.values()):
        return 400, {'error': '查询参数无效'}
    if name == 'tasks' and 'claimed' in params and params['claimed'][0] not in ('true', 'false'):
        return 400, {'error': '领取状态无效'}
    if '{id}' in path:
        identifier = params.get('id', [''])[0]
        if not re.fullmatch(r'[A-Za-z0-9_.:-]{1,128}', identifier):
            return 400, {'error': '记录 ID 无效'}
        path = path.replace('{id}', identifier)
        params = {k: v for k, v in params.items() if k != 'id'}
    endpoint = os.environ.get('FIELDSTATION_' + service.upper() + '_URL', '')
    token = os.environ.get('FIELDSTATION_' + service.upper() + '_TOKEN', '')
    if not endpoint or not token:
        return 503, {'error': '尚未配置连接', 'state': 'unconfigured'}
    url = urlsplit(endpoint)
    if url.scheme not in ('http', 'https') or not url.hostname or url.username or url.password or url.path not in ('', '/') or url.query or url.fragment or not token.isascii() or any(c.isspace() for c in token):
        return 503, {'error': '连接配置无效', 'state': 'unconfigured'}
    query = urlencode({k: v[0] for k, v in params.items() if v[0]})
    request = Request(endpoint.rstrip('/') + path + ('?' + query if query else ''), headers={'Authorization': 'Bearer ' + token, 'Accept': 'application/json'})
    try:
        with build_opener(NoRedirect()).open(request, timeout=5) as response:
            raw = response.read(2 * 1024 * 1024 + 1)
            if len(raw) > 2 * 1024 * 1024:
                raise ValueError('response too large')
            data = json.loads(raw)
            if not isinstance(data, dict):
                raise ValueError('invalid response')
            return 200, data.get('result', data) if service == 'im' else data
    except HTTPError as exc:
        return exc.code, {'error': '服务拒绝读取' if exc.code in (401, 403) else '服务返回错误', 'status': exc.code}
    except (URLError, OSError, ValueError, UnicodeError):
        return 502, {'error': '无法读取服务，请检查连接', 'state': 'unavailable'}

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        url = urlsplit(self.path)
        if url.path in ('/', '/im.js', '/im.css', '/graph.js'):
            filename = {'/': 'index.html', '/im.js': 'im.js', '/im.css': 'im.css', '/graph.js': 'graph.js'}[url.path]
            body = (HERE / filename).read_bytes()
            self.send_response(200)
            self.send_header('Content-Type', {'/': 'text/html', '/im.js': 'text/javascript', '/im.css': 'text/css', '/graph.js': 'text/javascript'}[url.path] + '; charset=utf-8')
        elif re.fullmatch(r'/api/[a-z]+', url.path) and url.path[5:] in ROUTES:
            try:
                status, value = read_source(url.path[5:], parse_qs(url.query, keep_blank_values=True, strict_parsing=True))
            except ValueError:
                status, value = 400, {'error': '查询参数无效'}
            body = json.dumps(value, ensure_ascii=False).encode('utf-8')
            self.send_response(status)
            self.send_header('Content-Type', 'application/json; charset=utf-8')
        else:
            self.send_error(404)
            return
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        pass

def main():
    port = int(os.environ.get('FIELDSTATION_CONSOLE_PORT', '18765'))
    with ThreadingHTTPServer(('127.0.0.1', port), Handler) as server:
        print(f'Fieldstation console: http://127.0.0.1:{port}', flush=True)
        server.serve_forever()


if __name__ == '__main__':
    main()
