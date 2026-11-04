"""Trusted local project host. Component business data is opaque to this layer."""
from __future__ import annotations

import argparse
import contextlib
import hashlib
import http.client
import os
import shutil
import threading
import time
import unicodedata
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from uuid import uuid4

from .archive import FORMAT, MAX_ARCHIVE, canonical, digest, load, pack, safe_name, unpack


def outside(path: str | Path) -> Path:
    raw = Path(path)
    checkout = Path(__file__).resolve().parents[1]
    result = raw.resolve()
    if not raw.is_absolute() or result == checkout or checkout in result.parents:
        raise ValueError("host directories must be absolute and outside checkout")
    return result


def save(path: Path, value: dict):
    temporary = path.with_suffix(".writing")
    with temporary.open("wb") as stream:
        stream.write(canonical(value))
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


class HostMutex:
    """Reentrant within a thread, process-locked across hosts sharing a runtime."""
    locks: dict[str, threading.RLock] = {}
    registry_lock = threading.Lock()

    def __init__(self, root: Path):
        self.root = root
        with self.registry_lock:
            self.lock = self.locks.setdefault(str(root), threading.RLock())
        self.local = threading.local()

    def __enter__(self):
        self.lock.acquire()
        depth = getattr(self.local, 'depth', 0)
        if depth == 0:
            self.local.file_lock = publication_lock(self.root)
            try:
                self.local.file_lock.__enter__()
            except BaseException:
                self.lock.release()
                raise
        self.local.depth = depth + 1
        return self

    def __exit__(self, kind, value, trace):
        self.local.depth -= 1
        try:
            if self.local.depth == 0:
                self.local.file_lock.__exit__(kind, value, trace)
        finally:
            self.lock.release()


@contextlib.contextmanager
def publication_lock(parent: Path):
    with (parent / ".project-publish.lock").open("a+b") as stream:
        if stream.tell() == 0:
            stream.write(b"0")
            stream.flush()
        stream.seek(0)
        if os.name == "nt":
            import msvcrt

            msvcrt.locking(stream.fileno(), msvcrt.LK_LOCK, 1)
        else:
            import fcntl

            getattr(fcntl, 'flock')(stream, getattr(fcntl, 'LOCK_EX'))
        try:
            yield
        finally:
            stream.seek(0)
            if os.name == "nt":
                msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                getattr(fcntl, 'flock')(stream, getattr(fcntl, 'LOCK_UN'))


class ComponentClient:
    def __init__(self, endpoint: str, token: str):
        parsed = urllib.parse.urlsplit(endpoint)
        if parsed.scheme != 'http' or parsed.hostname not in {'127.0.0.1', 'localhost'} or parsed.path not in {'', '/'} or parsed.query or parsed.fragment or '@' in parsed.netloc:
            raise ValueError("component endpoint must be bound loopback HTTP")
        self.endpoint, self.token = endpoint.rstrip('/'), token

    def call(self, operation: str, body: dict | None = None) -> dict:
        request = urllib.request.Request(self.endpoint + '/v1/project-component/' + operation,
                                         data=canonical(body) if body is not None else None,
                                         headers={'Authorization': 'Bearer ' + self.token, 'Content-Type': 'application/json'})
        try:
            with urllib.request.urlopen(request, timeout=120) as response:
                raw = response.read(8 * 1024**2 + 1)
        except urllib.error.HTTPError as exc:
            details = load(exc.read(1024**2))
            raise ValueError(f"Component rejected ({exc.code}): {details.get('message', 'request failed')}") from None
        if len(raw) > 8 * 1024**2:
            raise ValueError('component metadata budget exceeded')
        return load(raw)['result']

    def download(self, operation: str, target: Path):
        request = urllib.request.Request(self.endpoint + '/v1/project-component/' + operation,
                                         headers={'Authorization': 'Bearer ' + self.token})
        with urllib.request.urlopen(request, timeout=120) as response, target.open('xb') as output:
            remaining = int(response.headers['Content-Length'])
            if not 0 < remaining <= MAX_ARCHIVE:
                raise ValueError('component transfer exceeds budget')
            while remaining:
                chunk = response.read(min(1024 * 1024, remaining))
                if not chunk:
                    raise ValueError('component download interrupted')
                output.write(chunk)
                remaining -= len(chunk)

    def upload(self, source: Path) -> str:
        parsed = urllib.parse.urlsplit(self.endpoint)
        connection = http.client.HTTPConnection(str(parsed.hostname), parsed.port, timeout=120)
        try:
            connection.putrequest('POST', '/v1/project-component/upload')
            connection.putheader('Authorization', 'Bearer ' + self.token)
            connection.putheader('Content-Type', 'application/octet-stream')
            connection.putheader('Content-Length', str(source.stat().st_size))
            connection.endheaders()
            with source.open('rb') as stream:
                for chunk in iter(lambda: stream.read(1024 * 1024), b''):
                    connection.send(chunk)
            response = connection.getresponse()
            data = load(response.read(1024**2))
            if response.status != 200:
                raise ValueError(data.get('message', 'component upload failed'))
            return data['result']['upload_id']
        finally:
            connection.close()


class ProjectHost:
    def __init__(self, endpoint: str, token: str, root: str, runtime: Path,
                 project_parent: Path, *, queue_store=None, export_orchestration: bool = False,
                 static_dir: Path | None = None):
        if queue_store is not None or export_orchestration or static_dir is not None:
            raise ValueError('legacy orchestration and dashboard are unsupported in this version')
        self.client = ComponentClient(endpoint, token)
        self.root = root
        self.history_origin = 'source'
        self.runtime, self.parent = outside(runtime), outside(project_parent)
        self.identity = hashlib.sha256(canonical([str(self.runtime), root])).hexdigest()
        if self.runtime == self.parent or self.runtime in self.parent.parents or self.parent in self.runtime.parents:
            raise ValueError('project parent and host runtime must be separate directories')
        binding_file = self.runtime / 'binding.json'
        if self.runtime.exists():
            if binding_file.is_file():
                if load(binding_file.read_bytes()).get('host_contract') != 'im-only-v1':
                    raise ValueError('legacy project host runtime is unsupported; use a fresh runtime')
            elif any(self.runtime.iterdir()):
                raise ValueError('unbound project host runtime is unsupported; use a fresh runtime')
        # Authenticate a first binding before creating any durable host state. A
        # rejected or unavailable component can then be retried at the same path.
        initial_info = None if binding_file.is_file() else self.client.call('info')
        if initial_info is not None:
            initial_info['instance_id']  # Validate required identity before writing.
        self.runtime.mkdir(parents=True, exist_ok=True)
        self.parent.mkdir(parents=True, exist_ok=True)
        for name in ('uploads', 'exports', 'inspections', 'operations'):
            (self.runtime / name).mkdir(exist_ok=True)
        self.lock = HostMutex(self.runtime)
        self.fault_injector = None
        with self.lock:
            expected = {'root': root, 'project_parent': str(self.parent), 'host_contract': 'im-only-v1'}
            saved = load(binding_file.read_bytes()) if binding_file.exists() else None
            if saved and any(saved.get(k) != v for k, v in expected.items()):
                raise ValueError('host runtime is bound to another project; use a new runtime')
            try:
                info = initial_info if initial_info is not None else self.client.call('info')
            except urllib.error.URLError:
                if not saved:
                    raise
            else:
                if saved and saved.get('instance_id') != info['instance_id']:
                    raise ValueError('source installation identity changed; use a new host runtime')
                save(binding_file, {**expected, 'instance_id': info['instance_id']})
            self.recover()
            self.cleanup_expired_uploads()

    def fault(self, point: str):
        if self.fault_injector:
            self.fault_injector(point)

    @staticmethod
    def key(value: str) -> str:
        if not isinstance(value, str) or not 1 <= len(value) <= 256:
            raise ValueError('operation id must contain 1..256 characters')
        return hashlib.sha256(value.encode('utf-8')).hexdigest()

    @staticmethod
    def opaque(value: str) -> str:
        if not isinstance(value, str) or len(value) != 64 or any(c not in '0123456789abcdef' for c in value):
            raise ValueError('invalid opaque id')
        return value

    def capabilities(self) -> dict:
        return {'enabled': True, 'orchestration_bound': False,
                'orchestration_authorized': False,
                'max_upload_bytes': MAX_ARCHIVE, 'scope': '整个 IM 账本和受管附件',
                'message': '仅支持 IM 组件；外部来源只保留引用；导入重建认证并隔离执行'}

    def export(self, request_id: str, include_orchestration: bool) -> dict:
        if type(include_orchestration) is not bool:
            raise ValueError('include_orchestration must be boolean')
        key = self.key(request_id)
        receipt = self.runtime / 'exports' / f'{key}.json'
        with self.lock:
            if include_orchestration:
                raise ValueError('legacy orchestration export is unsupported in this version')
            if receipt.exists():
                result = load(receipt.read_bytes())
                if result['include_orchestration'] != include_orchestration:
                    raise ValueError('export request id conflicts with options')
                return result
            work = self.runtime / 'exports' / (key + '.work')
            if work.exists():
                shutil.rmtree(work)
            work.mkdir()
            target = self.runtime / 'exports' / (key + '.improjectpkg')
            try:
                core = self.client.call('export', {'request_id': request_id})
                self.client.download('download/' + core['job_id'], work / 'im.component')
                components = {'im': core['metadata']}
                manifest = {'format': FORMAT, 'generator': 'project-host/v1', 'package_id': key,
                            'generator_code_sha256': hashlib.sha256(Path(__file__).read_bytes() + Path(__file__).with_name('archive.py').read_bytes()).hexdigest(),
                            'default_root': self.root, 'components': components,
                            'orchestration_status': 'unbound',
                            'snapshot_semantics': 'independent-components',
                            'execution_policy': 'isolated-on-install',
                            'reference_diagnostic': 'IM external references are declared and not downloaded'}
                target.unlink(missing_ok=True)
                pack(work, target, manifest)
                result = {'job_id': key, 'state': 'complete', 'include_orchestration': include_orchestration,
                          'metadata': manifest, 'bytes': target.stat().st_size, 'sha256': digest(target)}
                save(receipt, result)
                return result
            finally:
                shutil.rmtree(work)

    def register_upload(self, file: Path) -> dict:
        key = digest(file)
        destination = self.runtime / 'uploads' / (key + '.improjectpkg')
        with self.lock:
            if not destination.exists():
                file.rename(destination)
            else:
                file.unlink()
        return {'upload_id': key, 'bytes': destination.stat().st_size, 'sha256': key}

    def preflight(self, upload_id: str) -> dict:
        key = self.opaque(upload_id)
        receipt = self.runtime / 'inspections' / (key + '.json')
        with self.lock:
            if receipt.exists():
                cached = load(receipt.read_bytes())
                if 'orchestration' in cached['components']:
                    raise ValueError('legacy orchestration packages are unsupported in this version')
                return cached
            directory = self.runtime / 'inspections' / key
            if directory.exists():
                shutil.rmtree(directory)
            try:
                manifest = unpack(self.runtime / 'uploads' / (key + '.improjectpkg'), directory)
                allowed = {'format', 'generator', 'generator_code_sha256', 'package_id', 'default_root', 'components', 'orchestration_status',
                           'snapshot_semantics', 'execution_policy', 'reference_diagnostic', 'files'}
                if set(manifest) != allowed or not isinstance(manifest['components'], dict):
                    raise ValueError('unexpected project manifest fields')
                if manifest['snapshot_semantics'] != 'independent-components' or manifest['execution_policy'] != 'isolated-on-install':
                    raise ValueError('unsupported snapshot or execution contract')
                components = manifest['components']
                if set(components) not in ({'im'}, {'im', 'orchestration'}):
                    raise ValueError('invalid component inventory')
                expected = {'im.component', *({'queue.sqlite'} if 'orchestration' in components else set())}
                if {item['path'] for item in manifest['files']} != expected:
                    raise ValueError('unexpected project payload')
                if 'orchestration' in components:
                    raise ValueError('legacy orchestration packages are unsupported in this version')
                core_id = self.client.upload(directory / 'im.component')
                core = self.client.call('validate/' + core_id, {})
                if core != components['im'] or manifest['default_root'] not in core['roots']:
                    raise ValueError('component metadata/root mismatch')
                summary = {'upload_id': key, 'format': FORMAT, 'root': manifest['default_root'],
                           'roots': core['roots'], 'components': components,
                           'external_reference_count': core['external_reference_count'],
                           'message': '创建新项目；重建本机认证；执行、自动派发及旧租约全部隔离；外部引用不下载'}
                result = {**summary, 'preflight_hash': hashlib.sha256(canonical(summary)).hexdigest(), 'component_upload_id': core_id}
                save(receipt, result)
                return result
            except BaseException:
                if directory.exists():
                    shutil.rmtree(directory)
                raise

    def install(self, upload_id: str, preflight_hash: str, name: str, operation_id: str) -> dict:
        name = safe_name(name)
        if name.startswith('.'):
            raise ValueError('hidden/host-reserved project names are forbidden')
        key = self.key(operation_id)
        intent = {'upload_id': upload_id, 'preflight_hash': preflight_hash, 'name': name}
        journal = self.runtime / 'operations' / (key + '.json')
        stage = self.parent / ('.project-stage-' + key[:16])
        destination = self.parent / name
        with self.lock, publication_lock(self.parent):
            self.recover()
            if journal.exists():
                saved = load(journal.read_bytes())
                if saved['intent'] != intent:
                    raise ValueError('installation operation id conflicts with intent')
                if saved['state'] == 'complete':
                    if saved['receipt'].get('orchestration'):
                        raise ValueError('legacy orchestration installations are unsupported in this version')
                    return saved['receipt']
            else:
                saved = {'operation_id': key, 'intent': intent, 'state': 'preparing'}
            if any(unicodedata.normalize('NFC', p.name).casefold() == name.casefold() for p in self.parent.iterdir()):
                raise ValueError('project name already exists; no merge or overwrite')
            inspected = self.preflight(upload_id)
            if 'orchestration' in inspected['components']:
                raise ValueError('legacy orchestration packages are unsupported in this version')
            if inspected['preflight_hash'] != preflight_hash:
                raise ValueError('preflight hash does not match upload')
            save(journal, saved)
            if stage.exists():
                shutil.rmtree(stage)
            stage.mkdir()
            try:
                self.fault('before_prepare')
                core_id = inspected['component_upload_id']
                prepared = self.runtime / 'operations' / (key + '.prepared')
                if not prepared.exists():
                    self.client.call('prepare/' + core_id, {})
                    self.client.download('prepared/' + core_id, prepared)
                    saved['prepared_sha256'] = digest(prepared)
                    save(journal, saved)
                elif saved.get('prepared_sha256') != digest(prepared):
                    prepared.unlink()
                    raise ValueError('interrupted prepared transfer; retry original operation')
                unpack(prepared, stage / 'im', expected_format='issue-manager-prepared-component/v1')
                self.fault('after_authentication')
                self.fault('after_components')
                receipt = {'installation_id': key, 'name': name, 'state': 'complete', 'root': inspected['root'],
                           'orchestration': 'orchestration' in inspected['components'], 'execution_isolated': True,
                           'message_store': 'unsupported',
                           'upload_sha256': upload_id}
                save(stage / 'installation.json', receipt)
                saved.update(state='publishing', receipt=receipt)
                save(journal, saved)
                self.fault('before_publish')
                os.rename(stage, destination)
                self.fault('after_publish')
                saved['state'] = 'complete'
                save(journal, saved)
                prepared.unlink(missing_ok=True)
                self.fault('after_receipt')
                return receipt
            except BaseException:
                if stage.exists():
                    shutil.rmtree(stage)
                raise

    def recover(self):
        for journal in (self.runtime / 'operations').glob('*.json'):
            saved = load(journal.read_bytes())
            if saved.get('receipt', {}).get('orchestration'):
                continue
            name = safe_name(saved['intent']['name'])
            marker = self.parent / name / 'installation.json'
            if saved['state'] == 'publishing' and marker.is_file():
                receipt = load(marker.read_bytes())
                if receipt != saved['receipt'] or receipt['installation_id'] != saved['operation_id']:
                    raise ValueError('installation recovery marker mismatch')
                save(journal, {**saved, 'state': 'complete'})

    def receipt(self, installation_id: str) -> dict:
        saved = load((self.runtime / 'operations' / (self.opaque(installation_id) + '.json')).read_bytes())
        if saved['state'] != 'complete':
            raise ValueError('installation is not complete; retry original intent')
        return saved['receipt']

    def cancel(self, upload_id: str) -> dict:
        key = self.opaque(upload_id)
        with self.lock:
            for journal in (self.runtime / 'operations').glob('*.json'):
                state = load(journal.read_bytes())
                if state['intent']['upload_id'] == key and state['state'] != 'complete':
                    return {'cancelled': False, 'message': '安装操作已提交；保留回执并使用同一操作恢复'}
            receipt = self.runtime / 'inspections' / (key + '.json')
            if receipt.exists():
                info = load(receipt.read_bytes())
                self.client.call('discard/' + info['component_upload_id'], {})
            directory = self.runtime / 'inspections' / key
            if directory.exists():
                if not directory.resolve().is_relative_to((self.runtime / 'inspections').resolve()):
                    raise ValueError('cleanup target escaped host staging')
                shutil.rmtree(directory)
            receipt.unlink(missing_ok=True)
            (self.runtime / 'uploads' / (key + '.improjectpkg')).unlink(missing_ok=True)
            return {'cancelled': True}

    def cleanup_expired_uploads(self) -> None:
        """Bounded startup cleanup; pending intents and installed projects are never targets."""
        pending = {load(path.read_bytes())['intent']['upload_id']
                   for path in (self.runtime / 'operations').glob('*.json')
                   if load(path.read_bytes())['state'] != 'complete'}
        for file in list((self.runtime / 'uploads').glob('*.receiving'))[:100]:
            if time.time() - file.stat().st_mtime > 86400:
                file.unlink(missing_ok=True)
        for file in list((self.runtime / 'uploads').glob('*.improjectpkg'))[:100]:
            key = file.stem
            if len(key) != 64 or key in pending or time.time() - file.stat().st_mtime < 86400:
                continue
            # Component discard is optional while source is offline; own host state remains recoverable.
            try:
                self.cancel(key)
            except (OSError, ValueError):
                continue

    def open(self, installation_id: str) -> dict:
        raise ValueError('legacy dashboard is unsupported in this version')

    def close(self):
        pass

    @staticmethod
    def public_summary(result: dict) -> dict:
        """Keep JSON control responses small; exhaustive file inventories stay in archives."""
        result = {key: value for key, value in result.items() if key != 'component_upload_id'}
        for field in ('metadata',):
            if field in result:
                result[field] = dict(result[field])
        container = result.get('metadata', result)
        if 'components' in container:
            container['components'] = {
                name: {**{key: value for key, value in component.items() if key != 'files'},
                       'file_count': len(component.get('files', []))}
                for name, component in container['components'].items()
            }
        return result

    def handle(self, handler):
        from urllib.parse import urlsplit

        parsed = urlsplit(handler.path)
        operation = parsed.path.removeprefix('/api/projects/')
        try:
            if parsed.query:
                raise ValueError('project routes do not accept query parameters')
            if handler.command == 'GET' and operation == 'capabilities':
                handler._json(200, self.capabilities())
                return
            if handler.command == 'GET' and operation == 'info':
                handler._json(200, self.client.call('info'))
                return
            if handler.command == 'GET' and operation.startswith('job/'):
                key = self.opaque(operation.split('/')[1])
                handler._json(200, self.public_summary(load((self.runtime / 'exports' / (key + '.json')).read_bytes())))
                return
            if handler.command == 'GET' and operation.startswith('download/'):
                key = self.opaque(operation.split('/')[1])
                result = load((self.runtime / 'exports' / (key + '.json')).read_bytes())
                if result['include_orchestration']:
                    raise ValueError('legacy orchestration export is unsupported in this version')
                if result['state'] != 'complete':
                    raise ValueError('export is not ready')
                path = self.runtime / 'exports' / (key + '.improjectpkg')
                handler.send_response(200)
                handler.send_header('Content-Type', 'application/octet-stream')
                handler.send_header('Content-Disposition', 'attachment; filename="project.improjectpkg"')
                handler.send_header('Content-Length', str(path.stat().st_size))
                handler.send_header('Cache-Control', 'no-store')
                handler.end_headers()
                with path.open('rb') as stream:
                    shutil.copyfileobj(stream, handler.wfile, 1024 * 1024)
                return
            if handler.command == 'GET' and operation.startswith('receipt/'):
                handler._json(200, self.receipt(operation.split('/')[1]))
                return
            if handler.command != 'POST':
                raise ValueError('unknown project route')
            if operation == 'upload':
                file = self.runtime / 'uploads' / (uuid4().hex + '.receiving')
                # Same finite streaming contract, kept independent of either runtime package.
                size = int(handler.headers.get('Content-Length', '0'))
                if not 0 < size <= MAX_ARCHIVE or handler.headers.get('Transfer-Encoding'):
                    raise ValueError('upload outside budget')
                if shutil.disk_usage(self.runtime).free < size * 4 + 16 * 1024**2:
                    raise ValueError('insufficient upload disk space')
                handler.connection.settimeout(60)
                try:
                    with file.open('xb') as output:
                        remaining = size
                        while remaining:
                            chunk = handler.rfile.read(min(1024 * 1024, remaining))
                            if not chunk:
                                raise ValueError('upload interrupted')
                            output.write(chunk)
                            remaining -= len(chunk)
                    handler._json(200, self.register_upload(file))
                finally:
                    file.unlink(missing_ok=True)
                return
            size = int(handler.headers.get('Content-Length', '0'))
            if not 0 < size <= 64 * 1024 or handler.headers.get('Content-Type') != 'application/json':
                raise ValueError('invalid bounded project request')
            body = load(handler.rfile.read(size))
            fields = {'export': {'request_id', 'include_orchestration'}, 'preflight': {'upload_id'},
                      'install': {'upload_id', 'preflight_hash', 'name', 'operation_id'}, 'open': {'installation_id'}, 'cancel': {'upload_id'}}
            if operation not in fields or not isinstance(body, dict) or set(body) != fields[operation]:
                raise ValueError('unknown operation or forged project fields')
            result = getattr(self, operation)(**body)
            handler._json(200, self.public_summary(result))
        except OSError as exc:
            if operation == 'install':
                handler._json(503, {'error': 'project_unconfirmed', 'message': str(exc) + '; retry the same installation operation'})
            else:
                handler._json(400, {'error': 'project_rejected', 'message': str(exc)})
        except (ValueError, KeyError) as exc:
            handler._json(400, {'error': 'project_rejected', 'message': str(exc)})


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--endpoint', default=os.environ.get('IM_ENDPOINT'))
    parser.add_argument('--root', required=True)
    parser.add_argument('--runtime', required=True)
    parser.add_argument('--project-parent', required=True)
    parser.add_argument('--queue')
    parser.add_argument('--export-orchestration', action='store_true')
    commands = parser.add_subparsers(dest='command', required=True)
    serve = commands.add_parser('serve')
    serve.add_argument('--static-dir', required=True)
    serve.add_argument('--port', type=int, default=5318)
    serve.add_argument('--write-scope', action='append', default=[])
    export = commands.add_parser('export')
    export.add_argument('--request-id', required=True)
    export.add_argument('--include-orchestration', action='store_true')
    inspect = commands.add_parser('inspect')
    inspect.add_argument('--file', required=True)
    install = commands.add_parser('install')
    install.add_argument('--upload-id', required=True)
    install.add_argument('--preflight-hash', required=True)
    install.add_argument('--name', required=True)
    install.add_argument('--operation-id', required=True)
    args = parser.parse_args(argv)
    if args.queue or args.export_orchestration or args.command == 'serve' or (args.command == 'export' and args.include_orchestration):
        parser.error('legacy orchestration and dashboard are unsupported in this version')
    host = ProjectHost(args.endpoint, os.environ['IM_PROJECT_TOKEN'], args.root,
                       Path(args.runtime), Path(args.project_parent))
    if args.command == 'export':
        result = host.export(args.request_id, args.include_orchestration)
    elif args.command == 'inspect':
        file = host.runtime / 'uploads' / (uuid4().hex + '.receiving')
        shutil.copyfile(outside(args.file), file)
        result = host.preflight(host.register_upload(file)['upload_id'])
    elif args.command == 'install':
        result = host.install(args.upload_id, args.preflight_hash, args.name, args.operation_id)
    print(canonical(result).decode('utf-8'))


if __name__ == '__main__':
    main()
