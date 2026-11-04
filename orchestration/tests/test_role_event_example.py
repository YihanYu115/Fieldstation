"""The optional policy must not fabricate work from a quiet scan."""
from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path

import pytest

path = Path(__file__).resolve().parents[1] / 'examples/python_role_events.py'
spec = spec_from_file_location('role_event_example', path)
module = module_from_spec(spec)
spec.loader.exec_module(module)


class Observations:
    def __init__(self, records, scans):
        self.records, self.scans, self.activations = records, scans, []

    def listen(self, *args, **kwargs):
        pass

    def poll(self, every):
        yield self.scans

    def pending(self, watch):
        return iter(self.records.get(watch, []))

    def activate(self, candidate, **kwargs):
        self.activations.append((candidate, kwargs))
        return {'outcome': 'accepted'}


def test_quiet_is_not_a_scientist_trigger_and_real_requests_remain_distinct():
    quiet = Observations({}, [])
    module.run(quiet)
    assert quiet.activations == []
    candidates = {key: [{'source': {'item_id': key}}] for key in
                  ('role-work', 'material', 'manager-request', 'scientist-request')}
    observed = Observations(candidates, [])
    module.run(observed)
    assert [item[0]['source']['item_id'] for item in observed.activations] == list(candidates)
    assert [item[1].get('role_profile') for item in observed.activations] == [None, 'curator', 'manager', 'scientist']


def test_failed_scan_cannot_activate_pending_work():
    observed = Observations({'scientist-request': [{'source': {'item_id': 'request'}}]}, [{'error': 'unavailable'}])
    with pytest.raises(RuntimeError):
        module.run(observed)
    assert observed.activations == []
