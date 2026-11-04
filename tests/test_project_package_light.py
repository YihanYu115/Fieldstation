from __future__ import annotations

import hashlib
import importlib.resources
import json
import shutil
import sqlite3
import stat
import zipfile
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace
from uuid import uuid4

import pytest

from issue_manager import IssueManager
from issue_manager.manager_api import ManagerService
from project_package import archive
from project_package.archive import canonical, safe_name, unpack
from project_package.host import ProjectHost


@pytest.fixture
def host(tmp_path):
    manager = IssueManager.initialize(tmp_path / 'ledger')
    manager.create_issue('ROOT', 'sample', 'test')
    token = json.loads(manager.credentials.path_for('maintenance-agent').read_text(encoding='utf-8'))['token']
    manager.close()
    service = ManagerService(tmp_path / 'ledger', port=0, project_runtime=tmp_path / 'components')
    endpoint = 'http://%s:%s' % service.start()
    host = ProjectHost(endpoint, token, 'ROOT', tmp_path / 'host', tmp_path / 'projects')
    try:
        yield host
    finally:
        host.close()
        service.close()


def test_im_only_roundtrip_and_original_operation_recovery(host):
    export = host.export('original-export', False)
    assert host.export('original-export', False) == export
    source = host.runtime / 'exports' / (export['job_id'] + '.improjectpkg')
    receiving = host.runtime / 'uploads' / (uuid4().hex + '.receiving')
    shutil.copyfile(source, receiving)
    inspected = host.preflight(host.register_upload(receiving)['upload_id'])
    assert set(inspected['components']) == {'im'}
    first = host.install(inspected['upload_id'], inspected['preflight_hash'], 'test-project', 'original-install')
    assert host.install(inspected['upload_id'], inspected['preflight_hash'], 'test-project', 'original-install') == first
    project = host.parent / 'test-project'
    assert (project / 'im').is_dir()
    assert not (project / 'orchestration').exists()
    snapshot = host.runtime / 'inspections' / inspected['upload_id'] / 'im.component'
    unpack(snapshot, host.runtime / 'test-source-snapshot', expected_format='issue-manager-im-component/v1')
    with sqlite3.connect(host.runtime / 'test-source-snapshot' / 'issue_ledger.sqlite') as source, \
            sqlite3.connect(project / 'im' / 'issue_ledger.sqlite') as target:
        excluded = {'actors', 'manager_metadata', 'audit_events', 'audit_checkpoints', 'domain_event_stream'}
        tables = [row[0] for row in source.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")]
        for table in tables:
            if table not in excluded:
                assert sorted(source.execute(f'SELECT * FROM "{table}"').fetchall(), key=repr) == \
                    sorted(target.execute(f'SELECT * FROM "{table}"').fetchall(), key=repr), table
        assert source.execute('SELECT stream_id FROM domain_event_stream').fetchone() != \
            target.execute('SELECT stream_id FROM domain_event_stream').fetchone()
    restored = IssueManager(project / 'im')
    try:
        assert restored.doctor()['ok']
        with pytest.raises(Exception):
            restored.credentials.resolve(host.client.token)
        new_token = json.loads(restored.credentials.path_for('maintenance-agent').read_text(encoding='utf-8'))['token']
        assert restored.credentials.resolve(new_token)
    finally:
        restored.close()
    with pytest.raises(ValueError, match='conflicts'):
        host.install(inspected['upload_id'], inspected['preflight_hash'], 'changed', 'original-install')


def test_split_origins_and_selected_relation_survive_project_package(host):
    from jsonschema import Draft202012Validator

    manager = IssueManager(host.runtime.parent / 'ledger')
    try:
        auth = manager.credentials.resolve(manager.credentials.path_for('organizer-agent'))
        source = manager.add_evidence(kind='external', locator='urn:source', issue_id='ROOT')['evidence_id']
        correction = manager.add_evidence(kind='external', locator='urn:correction', issue_id='ROOT')['evidence_id']
        relations = manager.scoped_evidence_relations
        old = relations.create(scope_issue_id='ROOT', source_evidence_id=correction, target_evidence_id=source,
            relation_type='refutes', rationale='count', auth=auth,
            expected_source_token=relations.binding(correction, auth=auth)['token'],
            expected_target_token=relations.binding(source, auth=auth)['token'], idempotency_key='correction')
        request = {'source_evidence_id': source,
            'expected_snapshot': manager.direct_splits.boundary(source, auth=auth)['snapshot'],
            'parts': [{'issue_id': 'ROOT', 'kind': 'observation', 'text': 'count'},
                      {'issue_id': 'ROOT', 'kind': 'interpretation', 'text': 'result'}],
            'relation_decisions': [{'relation_id': old['relation_id'], 'action': 'replace',
                                    'part_index': 0, 'reason': 'count only'}], 'new_relations': []}
        split = manager.direct_splits.split(request, auth=auth, idempotency_key='split')
        origins = manager.store.rows('SELECT * FROM direct_split_origins ORDER BY child_evidence_id')
    finally:
        manager.close()

    export = host.export('split-export', False)
    package = host.runtime / 'exports' / (export['job_id'] + '.improjectpkg')
    with zipfile.ZipFile(package) as archive_file:
        manifest = json.loads(archive_file.read('manifest.json'))
    schema = json.loads(importlib.resources.files('project_package').joinpath('contracts.json').read_text(encoding='utf-8'))
    Draft202012Validator({**schema, '$ref': '#/$defs/projectManifest'}).validate(manifest)
    Draft202012Validator({**schema, '$ref': '#/$defs/imComponentManifest'}).validate(manifest['components']['im'])
    receiving = host.runtime / 'uploads' / 'split.receiving'
    shutil.copyfile(package, receiving)
    inspected = host.preflight(host.register_upload(receiving)['upload_id'])
    host.install(inspected['upload_id'], inspected['preflight_hash'], 'split-project', 'split-install')
    restored = IssueManager(host.parent / 'split-project' / 'im')
    try:
        restored_auth = restored.credentials.resolve(restored.credentials.path_for('maintenance-agent'))
        assert restored.store.rows('SELECT * FROM direct_split_origins ORDER BY child_evidence_id') == origins
        assert not restored.scoped_evidence_relations.show(old['relation_id'], auth=restored_auth)['active']
        replacement = restored.scoped_evidence_relations.show(split['relations_created'][0]['relation_id'], auth=restored_auth)
        assert replacement['active'] and replacement['target_evidence_id'] == split['parts'][0]['evidence_id']
    finally:
        restored.close()


def test_unsupported_options_before_effects(host, tmp_path):
    with pytest.raises(ValueError, match='unsupported'):
        host.export('unsupported', True)
    assert not any(host.runtime.joinpath('exports').iterdir())
    with pytest.raises(ValueError, match='unsupported'):
        host.open('unused')
    with pytest.raises(ValueError, match='unsupported'):
        ProjectHost(host.client.endpoint, host.client.token, 'ROOT', tmp_path / 'other', tmp_path / 'other-projects', queue_store=object())
    assert not (tmp_path / 'other').exists()
    assert not (tmp_path / 'other-projects').exists()


def test_initial_auth_failure_can_retry_same_runtime(host, tmp_path):
    runtime, parent = tmp_path / 'fresh-runtime', tmp_path / 'fresh-projects'
    with pytest.raises(ValueError, match='Component rejected'):
        ProjectHost(host.client.endpoint, 'invalid-test-token', host.root, runtime, parent)
    assert not runtime.exists()
    assert not parent.exists()
    retry = ProjectHost(host.client.endpoint, host.client.token, host.root, runtime, parent)
    assert json.loads((runtime / 'binding.json').read_text(encoding='utf-8'))['host_contract'] == 'im-only-v1'
    retry.close()


def test_initial_unavailable_component_can_retry_same_runtime(tmp_path):
    import socket
    import urllib.error

    ledger = tmp_path / 'retry-ledger'
    manager = IssueManager.initialize(ledger)
    manager.create_issue('ROOT', 'sample', 'test')
    token = json.loads(manager.credentials.path_for('maintenance-agent').read_text(encoding='utf-8'))['token']
    manager.close()
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        port = sock.getsockname()[1]
    endpoint = f'http://127.0.0.1:{port}'
    runtime, parent = tmp_path / 'fresh-runtime', tmp_path / 'fresh-projects'
    with pytest.raises(urllib.error.URLError):
        ProjectHost(endpoint, token, 'ROOT', runtime, parent)
    assert not runtime.exists()
    assert not parent.exists()
    service = ManagerService(ledger, port=port, project_runtime=tmp_path / 'components')
    service.start()
    try:
        retry = ProjectHost(endpoint, token, 'ROOT', runtime, parent)
        assert json.loads((runtime / 'binding.json').read_text(encoding='utf-8'))['host_contract'] == 'im-only-v1'
        retry.close()
    finally:
        service.close()


@pytest.mark.parametrize('legacy_binding', [False, True])
def test_legacy_runtime_rejected_without_changing_bytes(host, tmp_path, legacy_binding):
    runtime, parent = tmp_path / 'legacy-runtime', tmp_path / 'fresh-projects'
    runtime.mkdir()
    marker = runtime / ('binding.json' if legacy_binding else 'legacy-data')
    marker.write_bytes(b'{"host_contract":"old"}' if legacy_binding else b'old state')
    before = {p.name: p.read_bytes() for p in runtime.iterdir()}
    with pytest.raises(ValueError, match='unsupported'):
        ProjectHost(host.client.endpoint, host.client.token, host.root, runtime, parent)
    assert {p.name: p.read_bytes() for p in runtime.iterdir()} == before
    assert not parent.exists()


def inspected_export(host, name):
    export = host.export(name, False)
    receiving = host.runtime / 'uploads' / (uuid4().hex + '.receiving')
    shutil.copyfile(host.runtime / 'exports' / (export['job_id'] + '.improjectpkg'), receiving)
    return host.preflight(host.register_upload(receiving)['upload_id'])


@pytest.mark.parametrize('point', ['before_prepare', 'after_authentication', 'after_components', 'before_publish', 'after_publish', 'after_receipt'])
def test_interrupted_original_install_recovers(host, point):
    inspected = inspected_export(host, 'source-' + point)
    def fault(current):
        if current == point:
            raise RuntimeError('injected')
    host.fault_injector = fault
    with pytest.raises(RuntimeError, match='injected'):
        host.install(inspected['upload_id'], inspected['preflight_hash'], 'recovery', 'original')
    host.fault_injector = None
    restarted = ProjectHost(host.client.endpoint, host.client.token, host.root, host.runtime, host.parent)
    try:
        result = restarted.install(inspected['upload_id'], inspected['preflight_hash'], 'recovery', 'original')
        assert result['state'] == 'complete'
        assert not (host.parent / ('.project-stage-' + host.key('original')[:16])).exists()
        assert not (host.parent / 'recovery' / 'orchestration').exists()
        with pytest.raises(ValueError, match='conflicts'):
            restarted.install(inspected['upload_id'], inspected['preflight_hash'], 'changed', 'original')
    finally:
        restarted.close()


def test_concurrent_publication_one_name(host):
    inspected = inspected_export(host, 'concurrent')
    def install(operation):
        try:
            return host.install(inspected['upload_id'], inspected['preflight_hash'], 'same', operation)['state']
        except ValueError:
            return 'rejected'
    with ThreadPoolExecutor(2) as pool:
        assert sorted(pool.map(install, ['one', 'two'])) == ['complete', 'rejected']
    assert (host.parent / 'same' / 'installation.json').is_file()


def test_cached_legacy_preflight_and_recovery_are_not_taken_over(host):
    from project_package.host import save
    key = 'a' * 64
    cached = {'components': {'im': {}, 'orchestration': {}}}
    receipt = host.runtime / 'inspections' / (key + '.json')
    save(receipt, cached)
    with pytest.raises(ValueError, match='unsupported'):
        host.preflight(key)
    operation = host.key('legacy')
    legacy = {'operation_id': operation, 'intent': {'name': 'legacy'}, 'state': 'publishing',
              'receipt': {'orchestration': True, 'installation_id': operation}}
    journal = host.runtime / 'operations' / (operation + '.json')
    save(journal, legacy)
    marker = host.parent / 'legacy' / 'installation.json'
    marker.parent.mkdir()
    save(marker, legacy['receipt'])
    before = journal.read_bytes()
    host.recover()
    assert journal.read_bytes() == before


def test_legacy_package_is_rejected_before_component_upload(host, tmp_path):
    from project_package.archive import pack, unpack
    export = host.export('source-for-legacy', False)
    original = host.runtime / 'exports' / (export['job_id'] + '.improjectpkg')
    payload = tmp_path / 'payload'
    metadata = unpack(original, payload)
    (payload / 'queue.sqlite').write_bytes(b'legacy queue fixture')
    metadata.pop('files')
    metadata['components']['orchestration'] = {'legacy': True}
    metadata['orchestration_status'] = 'included'
    target = host.runtime / 'uploads' / (uuid4().hex + '.receiving')
    pack(payload, target, metadata)
    upload = host.register_upload(target)
    before = set((tmp_path / 'components').rglob('*'))
    with pytest.raises(ValueError, match='unsupported'):
        host.preflight(upload['upload_id'])
    assert set((tmp_path / 'components').rglob('*')) == before
    assert not (host.runtime / 'inspections' / upload['upload_id']).exists()
    assert not (host.runtime / 'inspections' / (upload['upload_id'] + '.json')).exists()
    assert not list(host.parent.glob('.project-stage-*'))


@pytest.mark.parametrize('name', ['../outside', 'CON', 'AUX.txt', 'a\\b', 'a:b', 'a.', ' a ', '.', 'e\u0301'])
def test_unsafe_names(name):
    with pytest.raises(ValueError):
        safe_name(name)


@pytest.mark.parametrize('member', ['../escape', '/absolute', 'C:/drive', 'a\\b', 'CON'])
def test_malicious_members(tmp_path, member):
    file = tmp_path / 'bad.zip'
    with zipfile.ZipFile(file, 'w') as archive:
        archive.writestr(member, b'payload')
    with pytest.raises(ValueError):
        unpack(file, tmp_path / 'unpacked')
    assert not (tmp_path / 'unpacked').exists()


def test_component_export_rejects_unprivileged_actor(host, tmp_path):
    from project_package.host import ComponentClient
    manager = IssueManager(tmp_path / 'ledger')
    try:
        manager.credentials.issue_actor(actor_id='limited', actor_kind='organizer_agent',
            capabilities={'context.read'}, maintenance_credential=manager.credentials.path_for('maintenance-agent'))
        token = json.loads(manager.credentials.path_for('limited').read_text(encoding='utf-8'))['token']
    finally:
        manager.close()
    client = ComponentClient(host.client.endpoint, token)
    with pytest.raises(ValueError, match='rejected'):
        client.call('export', {'request_id': 'denied'})


def test_component_schema_tampering_is_rejected(host, tmp_path):
    from issue_manager.errors import ValidationError
    from issue_manager.project_component import export_component, validate_component
    from project_package.archive import pack

    manager = IssueManager(tmp_path / 'ledger')
    try:
        export_component(manager, tmp_path / 'component.zip')
    finally:
        manager.close()
    metadata = unpack(tmp_path / 'component.zip', tmp_path / 'component',
                      expected_format='issue-manager-im-component/v1')
    with sqlite3.connect(tmp_path / 'component' / 'issue_ledger.sqlite') as db:
        db.execute('CREATE VIEW malicious AS SELECT * FROM actors')
        db.commit()
    pack(tmp_path / 'component', tmp_path / 'tampered.zip',
         {key: value for key, value in metadata.items() if key != 'files'})
    with pytest.raises(ValidationError, match='Unexpected IM schema'):
        validate_component(tmp_path / 'tampered.zip', tmp_path / 'validation')
    assert not any(item['path'].startswith(('credentials', '.ledger_secret')) for item in metadata['files'])


def test_unknown_archive_format_is_rejected(tmp_path):
    raw = canonical({'format': 'old-workbench/v1', 'files': []})
    path = tmp_path / 'old.zip'
    with zipfile.ZipFile(path, 'w') as archive:
        archive.writestr('manifest.json', raw)
        archive.writestr('manifest.sha256', hashlib.sha256(raw).hexdigest())
    with pytest.raises(ValueError, match='unknown package format'):
        unpack(path, tmp_path / 'unpacked')
    assert not (tmp_path / 'unpacked').exists()


@pytest.mark.parametrize('kind', ['duplicate', 'case', 'unicode', 'symlink', 'bomb', 'extra', 'checksum', 'truncated'])
def test_hostile_container_rejected_without_target(tmp_path, kind):
    file = tmp_path / 'bad.improjectpkg'
    if kind == 'truncated':
        file.write_bytes(b'not zip')
    else:
        with zipfile.ZipFile(file, 'w', compression=zipfile.ZIP_DEFLATED if kind == 'bomb' else zipfile.ZIP_STORED) as z:
            data = b'a' * (2 * 1024**2 if kind == 'bomb' else 8)
            metadata = {'format': archive.FORMAT, 'files': [{'path': 'data', 'size': len(data), 'sha256': hashlib.sha256(data).hexdigest()}]}
            raw = canonical(metadata)
            z.writestr('manifest.json', raw)
            z.writestr('manifest.sha256', hashlib.sha256(raw).hexdigest())
            if kind == 'symlink':
                info = zipfile.ZipInfo('data')
                info.create_system = 3
                info.external_attr = (stat.S_IFLNK | 0o777) << 16
                z.writestr(info, data)
            else:
                z.writestr('data', b'changed!' if kind == 'checksum' else data)
            if kind in {'duplicate', 'case', 'unicode', 'extra'}:
                z.writestr({'duplicate': 'data', 'case': 'DATA', 'unicode': 'e\u0301', 'extra': 'extra'}[kind], b'bad')
    with pytest.raises(ValueError):
        unpack(file, tmp_path / 'stage')
    assert not (tmp_path / 'stage').exists()


@pytest.mark.parametrize('budget', ['MAX_ARCHIVE', 'MAX_TOTAL', 'MAX_FILE', 'MAX_FILES', 'MAX_MANIFEST', 'disk'])
def test_independent_budgets_and_disk_rejection(tmp_path, monkeypatch, budget):
    work = tmp_path / 'payload'
    work.mkdir()
    (work / 'data').write_bytes(b'a' * 1024)
    file = tmp_path / 'good.zip'
    archive.pack(work, file, {'format': archive.FORMAT})
    if budget == 'disk':
        monkeypatch.setattr(archive.shutil, 'disk_usage', lambda _: SimpleNamespace(free=0))
    else:
        monkeypatch.setattr(archive, budget, 0 if budget == 'MAX_FILES' else 1)
    with pytest.raises(ValueError):
        unpack(file, tmp_path / 'stage')
    assert not (tmp_path / 'stage').exists()


def test_im_export_preflight_cancel_has_bounded_memory_and_no_credentials(host):
    import tracemalloc
    tracemalloc.start()
    try:
        exported = host.export('measure', False)
        source = host.runtime / 'exports' / (exported['job_id'] + '.improjectpkg')
        receiving = host.runtime / 'uploads' / 'measure.receiving'
        shutil.copyfile(source, receiving)
        upload = host.register_upload(receiving)
        host.preflight(upload['upload_id'])
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert peak < 64 * 1024**2
    assert host.client.token.encode('utf-8') not in source.read_bytes()
    assert host.cancel(upload['upload_id'])['cancelled']
    assert not (host.runtime / 'uploads' / (upload['upload_id'] + '.improjectpkg')).exists()
    assert not (host.runtime / 'inspections' / upload['upload_id']).exists()
    with pytest.raises(ValueError, match='another project'):
        ProjectHost(host.client.endpoint, host.client.token, 'OTHER', host.runtime, host.parent)


def test_old_host_runtime_is_rejected_without_touching_it(host, tmp_path):
    legacy = tmp_path / 'legacy-runtime'
    legacy.mkdir()
    binding = legacy / 'binding.json'
    binding.write_text(json.dumps({'root': 'ROOT', 'project_parent': str(tmp_path / 'legacy-projects'),
                                  'instance_id': 'legacy'}), encoding='utf-8')
    artifact = legacy / 'old-upload.improjectpkg'
    artifact.write_bytes(b'old immutable evidence')
    before = {p.name: p.read_bytes() for p in legacy.iterdir()}
    with pytest.raises(ValueError, match='legacy project host runtime'):
        ProjectHost(host.client.endpoint, host.client.token, 'ROOT', legacy, tmp_path / 'legacy-projects')
    assert {p.name: p.read_bytes() for p in legacy.iterdir()} == before
    assert not (tmp_path / 'legacy-projects').exists()
