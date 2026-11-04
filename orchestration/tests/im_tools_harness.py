"""Isolated IM test host; kernel imports occur only here, never in product tools."""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

from queue_tools_harness import MCP, ManagedProcess
from workflow_orchestrator.im_client import IMClient
from workflow_orchestrator.im_tools import SPECS, IMTools

from issue_manager import IssueManager

ROOT = Path(__file__).resolve().parents[2]


class IMService:
    def __init__(self, path):
        self.path = path
        path.mkdir(parents=True, exist_ok=True)
        self.ledger = path / 'im-ledger'
        manager = IssueManager.initialize(self.ledger)
        try:
            manager.create_issue('P', 'sample', 'Synthetic isolated project')
            manager.create_issue('A', 'qubit', 'Failed experiment', parent_issue_id='P')
            manager.create_issue('B', 'qubit', 'Independent extra contribution', parent_issue_id='P')
            manager.create_issue('OUT', 'investigation', 'Outside the configured browse root')
            grants = {
                'experimenter': {'intake.submit', 'context.read'},
                'curator': {'context.read', 'evidence.write', 'evidence.relation.write', 'conclusion.record', 'conclusion.propose', 'issue.write'},
                'no-relations': {'context.read', 'evidence.write'},
                'reader': {'context.read'},
                'submit-only': {'intake.submit'},
            }
            self.tokens = {}
            for actor, capabilities in grants.items():
                manager.credentials.issue_actor(actor_id=actor, actor_kind='organizer_agent',
                    capabilities=capabilities, maintenance_credential=manager.credentials.path_for('maintenance-agent'))
                self.tokens[actor] = json.loads(manager.credentials.path_for(actor).read_text(encoding='utf-8'))['token']
        finally:
            manager.close()
        self.process = None
        self.start()

    def start(self):
        code = ('import json,sys; from issue_manager.manager_api import ManagerService; '
                'service=ManagerService(sys.argv[1],port=0); '
                'print(json.dumps({"address":service.address}),flush=True); '
                'service.serve_forever()')
        env = os.environ.copy()
        env['PYTHONPATH'] = str(ROOT)
        self.process = ManagedProcess([sys.executable, '-B', '-c', code, str(self.ledger)], self.path, env, 'im-service')
        try:
            host, port = json.loads(self.process.line())['address']
            self.endpoint = f'http://{host}:{port}'
        except BaseException:
            self.stop()
            raise

    def stop(self):
        if self.process:
            self.process.close()
            self.process = None

    def profile(self, actor='experimenter', *, tools=None, suffix='', endpoint=None):
        return {'surface': 'im', 'connection': {'endpoint': endpoint or self.endpoint, 'token_env': 'MCP_QUEUE_TOKEN'},
                'default_issue_id': 'A',
                'tools': tools or sorted(SPECS), 'journal_path': str(self.path / (actor + suffix + '-im-actions.json'))}

    def client(self, actor='experimenter', *, suffix='', endpoint=None):
        return IMClient(endpoint or self.endpoint, self.tokens[actor], self.path / (actor + suffix + '-im-actions.json'),
                        token_env='MCP_QUEUE_TOKEN')

    def tools(self, actor='experimenter', *, suffix='', endpoint=None):
        return IMTools(self.client(actor, suffix=suffix, endpoint=endpoint),
                       self.profile(actor, suffix=suffix, endpoint=endpoint))


class IMMCP(MCP):
    def __init__(self, service, actor='experimenter', profile=None):
        profile = profile or service.profile(actor)
        file = service.path / (actor + '-profile.json')
        file.write_text(json.dumps(profile), encoding='utf-8')
        super().__init__(service, principal=actor, profile=file)
