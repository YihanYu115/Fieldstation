import importlib.util
from pathlib import Path

path = Path(__file__).resolve().parents[1] / 'examples/dynamic_project_scheduler.py'
spec = importlib.util.spec_from_file_location('dynamic_project_scheduler', path)
policy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(policy)


class Listener:
    def __init__(self):
        self.watches = {}
        self.records = {}

    def listen(self, key, **kwargs):
        self.watches[key] = kwargs

    def pending(self, key, action_key=None):
        assert action_key == 'delivery'
        return self.records.get(key, [])

def test_human_research_entry_is_explicit_scientist_policy():
    listener = Listener()
    key = policy.watch_human_research(listener, 'ROOT')
    assert listener.watches[key] == {
        'kind': 'board.message', 'connection': 'board-scientist',
        'issue_id': 'ROOT', 'initial': 'new_only'}
    assert policy.human_research_activation() == {
        'host': 'host', 'role_profile': 'scientist', 'action_key': 'initial-scientist'}


def test_inbox_and_explicit_handoffs_are_independent():
    listener = Listener()
    watches = policy.install_watches(listener, ['A'], ['experimenter', 'curator', 'conclusion', 'scientist'])
    assert len(watches) == 7
    inbox = next(w for w in watches if w[1] == 'inbox')
    conclusion = next(w for w in watches if w[1:3] == ('handoff', 'conclusion'))
    assert listener.watches[inbox[0]] == {
        'kind': 'inbox.packet', 'connection': 'im-curator', 'issue_id': 'A', 'initial': 'from_start'}
    listener.records[inbox[0]] = [{'record': {'received_at': '2026-10-30T14:00:00+08:00'},
                                  'source': {'item_id': 'packet'}}]
    assert [(x[2], x[3]) for x in policy.candidates(listener, watches)] == [('inbox', 'curator')]
    listener.records[conclusion[0]] = [{'record': {'created_at': '2026-10-30T05:59:59+00:00'},
                                       'source': {'item_id': 'request'}}]
    assert [(x[2], x[3]) for x in policy.candidates(listener, watches)] == [
        ('inbox', 'curator'), ('handoff', 'conclusion')]


def test_pending_inbox_precedes_older_queue_and_handoff():
    listener = Listener()
    watches = policy.install_watches(listener, ['A'], ['experimenter', 'curator', 'scientist'])
    keys = {kind + '-' + role: key for key, kind, role, _ in watches}
    listener.records[keys['queue-experimenter']] = [
        {'record': {'created_at': '2026-10-30T06:00:00Z'}, 'source': {'item_id': 'task-1'}},
        {'record': {'created_at': '2026-10-30T06:01:00Z'}, 'source': {'item_id': 'task-2'}},
    ]
    listener.records[keys['inbox-curator']] = [
        {'record': {'received_at': '2026-10-30T06:02:00Z'}, 'source': {'item_id': 'packet'}}]
    listener.records[keys['handoff-scientist']] = [
        {'record': {'created_at': '2026-10-30T06:01:30Z'}, 'source': {'item_id': 'handoff'}}]
    assert [item[4]['source']['item_id'] for item in policy.candidates(listener, watches)] == [
        'packet', 'task-1', 'task-2', 'handoff']
    listener.records[keys['inbox-curator']] = []
    assert [item[4]['source']['item_id'] for item in policy.candidates(listener, watches)] == [
        'task-1', 'task-2', 'handoff']
