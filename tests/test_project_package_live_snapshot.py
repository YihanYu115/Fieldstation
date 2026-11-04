from __future__ import annotations

import json
import shutil
import sqlite3
from contextlib import closing

import pytest

from issue_manager import IssueManager
from issue_manager.manager_api import ManagerService
from issue_manager.project_component import export_component, validate_component
from project_package.archive import unpack
from project_package.host import ProjectHost


def test_live_wal_snapshot_and_missing_object_refusal(tmp_path):
    with closing(IssueManager.initialize(tmp_path / 'ledger')) as manager:
        manager.store.conn.execute('PRAGMA wal_autocheckpoint=0')
        manager.create_issue('ROOT', 'sample', 'Committed in active WAL')
        source = tmp_path / 'source.bin'
        source.write_bytes(b'Synthetic bytes')
        artifact = manager.artifacts.add(source, role='frozen', credential=manager.credentials.path_for('maintenance-agent'))
        assert manager.store.db_path.with_name('issue_ledger.sqlite-wal').stat().st_size > 0
        file = tmp_path / 'wal.component'
        export_component(manager, file)
        info = validate_component(file, tmp_path / 'validated')
        assert info['table_counts']['issues'] == 1
        with closing(sqlite3.connect(tmp_path / 'validated' / 'issue_ledger.sqlite')) as db:
            assert db.execute('SELECT title FROM issues').fetchone()[0] == 'Committed in active WAL'
        row = manager.store.row('SELECT storage_uri FROM artifacts WHERE artifact_id=?', (artifact['artifact_id'],))
        (manager.store.ledger_dir / row['storage_uri']).unlink()
        with pytest.raises(Exception, match='Missing or damaged'):
            export_component(manager, tmp_path / 'broken.component')
        assert not (tmp_path / 'broken.component').exists()


def test_restart_publishes_cached_prepared_components_while_source_offline(tmp_path):
    with closing(IssueManager.initialize(tmp_path / 'ledger')) as manager:
        manager.create_issue('ROOT', 'sample', 'Offline recovery')
        token = json.loads(manager.credentials.path_for('maintenance-agent').read_text(encoding='utf-8'))['token']
    service = ManagerService(tmp_path / 'ledger', port=0, project_runtime=tmp_path / 'components')
    endpoint = 'http://%s:%s' % service.start()
    host = ProjectHost(endpoint, token, 'ROOT', tmp_path / 'host', tmp_path / 'projects')
    try:
        exported = host.export('offline', False)
        incoming = host.runtime / 'uploads' / 'incoming.receiving'
        shutil.copyfile(host.runtime / 'exports' / (exported['job_id'] + '.improjectpkg'), incoming)
        inspected = host.preflight(host.register_upload(incoming)['upload_id'])
        def fail(point):
            if point == 'before_publish':
                raise OSError('Injected crash before publish')
        host.fault = fail
        with pytest.raises(OSError, match='Injected'):
            host.install(inspected['upload_id'], inspected['preflight_hash'], 'offline-project', 'offline-install')
    finally:
        host.close()
        service.close()
    restarted = ProjectHost(endpoint, token, 'ROOT', tmp_path / 'host', tmp_path / 'projects')
    try:
        result = restarted.install(inspected['upload_id'], inspected['preflight_hash'], 'offline-project', 'offline-install')
        assert result['state'] == 'complete'
        assert restarted.install(inspected['upload_id'], inspected['preflight_hash'], 'offline-project', 'offline-install') == result
        with closing(IssueManager(tmp_path / 'projects' / 'offline-project' / 'im')) as imported:
            assert imported.doctor()['ok']
        unpack(host.runtime / 'exports' / (exported['job_id'] + '.improjectpkg'), tmp_path / 'original-package')
    finally:
        restarted.close()
