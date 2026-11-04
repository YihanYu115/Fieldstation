"""Independent correct expectation for replay of an already confirmed admission."""

import pytest
from host_tools_harness import Host, publish, wait_for
from queue_tools_harness import evidence
from test_python_trigger import configuration, drain, services
from workflow_orchestrator.host_process import observe
from workflow_orchestrator.trigger_tools import TriggerTools


@pytest.mark.parametrize("offline", ["host", "source"])
def test_confirmed_original_is_not_reclassified_as_not_committed(tmp_path, monkeypatch, offline):
    with services(tmp_path, "queue") as src:
        q = src["queue"]
        with Host(tmp_path / "host", q, maximum=2, mode="hold") as host:
            publish(q)
            config = configuration(tmp_path, monkeypatch, src, host)
            t = TriggerTools(config, tmp_path / "state")
            t.listen("q", kind="queue.task", connection="queue", issue_id="A")
            drain(t)
            c = next(t.pending("q"))
            accepted = t.activate(c, host="host")
            assert accepted["outcome"] == "accepted"
            wait_for(lambda: len(host.starts()) == 1)
            current = host.client().by_request(accepted["request_id"])
            identity = current["run"]["process"]["identity"]
            host.capture_workers()
            assert observe(identity["pid"], identity)["state"] == "running"
            if offline == "host":
                host.stop()
            else:
                q.stop()
            repeated = t.activate(c, host="host")
            original = t._intent(t.state.associations()[0])
            still = observe(identity["pid"], identity)
            if offline == "host":
                host.start()
            else:
                q.start()
            confirmed = host.client().by_request(accepted["request_id"])
            ended = host.finish(confirmed)
            evidence(
                "review-confirmed-receipt-" + offline,
                {
                    "accepted": accepted,
                    "current_before_offline": current,
                    "repeat_during_offline": repeated,
                    "original_client_journal": original,
                    "worker_during_offline": still,
                    "confirmed_same_run": confirmed,
                    "exited": ended,
                    "starts": host.starts(),
                    "queue_counts": q.counts(),
                },
            )
            assert confirmed["run_id"] == accepted["run_id"] and still["state"] == "running"
            assert q.counts()["claims"] == 1 and len(host.starts()) == 1
            assert repeated["outcome"] == "accepted" and repeated["run_id"] == accepted["run_id"], (
                repeated
            )
