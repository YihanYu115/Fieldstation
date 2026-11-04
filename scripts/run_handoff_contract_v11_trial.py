"""Opt-in v1.1 handoff replay and held-out trial; trusted host, not production."""
from __future__ import annotations

import argparse
import asyncio
import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
from contextlib import closing
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("trial_harness", REPO / "scripts/run_handoff_contract_trial.py")
h = importlib.util.module_from_spec(spec)
spec.loader.exec_module(h)
OLD = Path("D:/实验记录/_issue_manager_handoff_contract_trial_20261003_047ecc47")
REPLAYS = ("N_weighting", "P_order_fix", "F_clipping", "C_migration")
NEW = ("I_retry", "U_calibration")
CASES = REPLAYS + NEW

SCRIPTS = {
    "I_retry": '''import json
def exercise(deduplicate):
    effects=[];cache={};attempts=0
    def deliver(key,payload,lose_reply=False):
        nonlocal attempts
        attempts+=1
        if deduplicate and key in cache:
            if cache[key]["payload"]!=payload: raise ValueError("same key different payload")
            return cache[key]
        record={"key":key,"payload":payload,"effect_index":len(effects)+1}
        effects.append(record)
        if deduplicate: cache[key]=record
        if lose_reply: raise TimeoutError("reply lost after effect")
        return record
    first_error=None
    try: deliver("job-17",{"value":7},True)
    except TimeoutError as e: first_error=type(e).__name__
    retry=deliver("job-17",{"value":7})
    repeated_snapshot={"attempts":attempts,"effects":list(effects),"retry":retry,"first_error":first_error}
    conflict=None
    if deduplicate:
        try: deliver("job-17",{"value":9})
        except ValueError as e: conflict={"type":type(e).__name__,"message":str(e)}
        deliver("job-18",{"value":7})
    return {"same_key_retry":repeated_snapshot,"conflict":conflict,"final_effects":effects}
print(json.dumps({"fixture_version":"retry-fixture-v3","old":exercise(False),"fixed":exercise(True),"persistence_tested":False,"concurrent_calls_tested":False,"real_network_used":False},ensure_ascii=False))
''',
    "U_calibration": '''import json
from datetime import datetime,timezone,timedelta
calibration=[{"counts":0,"reference_v":0.2},{"counts":1000,"reference_v":2.2}]
slope=(2.2-0.2)/(1000-0);intercept=0.2
def predict(x):return intercept+slope*x
validation=[{"counts":250,"reference_v":0.7},{"counts":750,"reference_v":1.7}]
for row in validation:
    row.update(predicted_v=predict(row["counts"]),absolute_error_v=abs(predict(row["counts"])-row["reference_v"]))
    row["pass"]=row["absolute_error_v"]<=0.01
clock_inputs=["2026-10-03T00:00:00+00:00","2026-10-03T16:30:00+00:00"]
clock=[{"utc":s,"local":datetime.fromisoformat(s).astimezone(timezone(timedelta(hours=8))).isoformat()} for s in clock_inputs]
print(json.dumps({"fixture":True,"calibration":calibration,"linear_model":{"slope_v_per_count":slope,"intercept_v":intercept},"validation":validation,"criterion_absolute_error_v":0.01,"calibration_interval_counts":[0,1000],"query_outside_interval":{"counts":1500,"predicted_v":predict(1500),"reference_v":None},"hardware_tested":False,"repeat_runs":1,"clock_display":{"utc_offset_hours":8,"rows":clock},"clock_source_accuracy_tested":False},ensure_ascii=False))
''',
}


def initialize(ledger, case, claims):
    with closing(h.IssueManager.initialize(ledger)) as manager:
        manager.create_issue(case, "investigation", "Handoff v1.1: " + case)
        for actor, caps in (("trial-author", {"intake.submit"}),
                            ("trial-curator", {"context.read", "evidence.write", "evidence.relation.write"}),
                            ("trial-reader", {"context.read"})):
            manager.credentials.issue_actor(actor_id=actor, actor_kind="experiment_agent",
                capabilities=caps, maintenance_credential=manager.credentials.path_for("maintenance-agent"))
        prior = []
        for index, claim in enumerate(claims):
            item = manager.add_evidence(kind="report", locator=f"trial-v11-prior:{case}/{index}",
                                       description=claim, issue_id=case)
            prior.append({"evidence_id": item["evidence_id"], "description": claim})
    return prior


def prepare(root):
    if (root / "plan.json").exists():
        raise ValueError("Already prepared; no resets")
    root.mkdir(parents=True, exist_ok=True)
    # Ask Git for literal Unicode paths rather than its default quoting.
    files = subprocess.check_output(["git", "-c", "core.quotePath=false", "ls-files", "-z", "--cached", "--others", "--exclude-standard"], cwd=REPO).decode("utf-8").split("\0")
    h.write(root / "workspace-before.json", {f: hashlib.sha256((REPO / f).read_bytes()).hexdigest() for f in files if f and (REPO / f).is_file()})
    for name in ("CURATOR_ROLE_CARD.md", "EXPERIMENTER_ROLE_CARD.md", "HANDOFF_CONTRACT.md"):
        shutil.copyfile(REPO / "orchestration" / name, root / name)
    shutil.copyfile(REPO / "scripts/run_handoff_contract_trial.py", root / "harness-frozen.py")
    shutil.copyfile(Path(__file__), root / "controller-frozen.py")
    h.write(root / "plan.json", {"version": "v1.1", "cases": list(CASES),
        "repetitions": {c: (1 if c in REPLAYS else 2) for c in CASES},
        "cohorts": {c: ("historical_packet_replay" if c in REPLAYS else "new_host_executed_work") for c in CASES},
        "model": h.MODEL, "endpoint": h.BASE, "thinking": "enabled", "reasoning_effort": "high",
        "author_sessions": 2, "curator_sessions": 8, "wall_seconds_per_session": 900,
        "model_requests_per_session": 40, "tool_attempts_per_session": 70, "max_tokens_per_request": 32768,
        "automatic_retries": 0, "semantic_repair": False,
        "comparison_limits": "single replay per old packet; no reliability estimate or randomized card control",
        "probe": "each actual contribution and prior temporarily refuted then withdrawn; original eligibility must restore"})
    for case in CASES:
        folder = root / case
        folder.mkdir()
        ledger = folder / "author-ledger"
        if case in REPLAYS:
            old_prior = h.read(OLD / case / "prior.json")
            prior = initialize(ledger, case, [x["description"] for x in old_prior])
            mapping = {a["evidence_id"]: b["evidence_id"] for a, b in zip(old_prior, prior)}
            packet = h.read(OLD / case / "packet.json")
            payload = {k: packet[k] for k in ("content", "attachment_refs", "sources")}
            payload["sources"] = [{k: s[k] for k in ("locator", "provided_text")} for s in payload["sources"]]
            raw = json.dumps(payload, ensure_ascii=False)
            for before, after in mapping.items():
                raw = raw.replace(before, after)
            payload = json.loads(raw)
            h.write(folder / "replay-payload.json", payload)
            h.write(folder / "replay-binding.json", {"old_root": str(OLD), "old_packet_id": packet["packet_id"],
                "old_content_sha256": packet["content_sha256"], "ID_mapping": mapping,
                "only_identity_substitution": True, "business_text_edited": False})
        else:
            prior = initialize(ledger, case, ["retry-fixture-v3 的 old 分支：job-17 的 value=7 已产生副作用后响应丢失，按同一个 key、同一个 payload 重试，不会产生第二次副作用。"] if case == "I_retry" else [])
            script = SCRIPTS[case]
            (folder / "work.py").write_text(script, encoding="utf-8")
            executed = subprocess.run([h.sys.executable, "-I", "-X", "utf8", str(folder / "work.py")], capture_output=True, timeout=30)
            (folder / "stdout.json").write_bytes(executed.stdout)
            (folder / "stderr.txt").write_bytes(executed.stderr)
            assert executed.returncode == 0
            execution = {"executor": "trusted host", "returncode": executed.returncode,
                "script_sha256": hashlib.sha256((folder / "work.py").read_bytes()).hexdigest(), "output_sha256": hashlib.sha256(executed.stdout).hexdigest(),
                "runs": 1, "synthetic_fixture": True, "environment": "local isolated Python; no hardware or real network"}
            h.write(folder / "execution.json", execution)
            task = ("交接超时后重试的副作用去重：说明 old 与 fixed 的实际结果、冲突 key 与不同 key 的结果、修复范围和未覆盖项；核对给出的旧判断。旧判断明确指向本脚本同一 retry-fixture-v3 的 old 分支及相同 job-17/value=7/响应丢失条件。"
                    if case == "I_retry" else "交接本轮线性校准计算、验证误差与区间外查询的效力范围，以及日志 UTC→UTC+8 时间显示结果。区分实际样例通过与未测范围；保留已有依据和两项工作的联系。")
            h.write(folder / "dossier.json", {"task": task, "execution": execution, "script": script,
                "actual_output": h.read(folder / "stdout.json"), "actual_stderr": executed.stderr.decode("utf-8"),
                "prior_contributions": prior, "prior_scope": "same fixture version and conditions explicitly matched" if prior else None,
                "attachments": [str(folder / n) for n in ("work.py", "stdout.json", "stderr.txt")],
                "capability": "宿主已实际执行；你负责根据材料交接，本模型没有独立执行能力。"})
        h.write(folder / "prior.json", prior)
    print("PREPARED " + str(root), flush=True)


async def run(root):
    if (root / "run-started.json").exists():
        raise ValueError("Already started; no automatic reruns")
    assert (REPO / "scripts/run_handoff_contract_trial.py").read_bytes() == (root / "harness-frozen.py").read_bytes()
    key = os.environ["DEEPSEEK_API_KEY"]
    h.write(root / "run-started.json", {"time_ns": h.time.time_ns(), "plan": h.read(root / "plan.json")})
    sessions = []
    try:
        with h.urlopen(h.Request(h.BASE + "/models", headers={"Authorization": "Bearer " + key}), timeout=30) as response:
            models = json.loads(response.read())
            assert h.MODEL in [x["id"] for x in models["data"]]
            h.write(root / "model-preflight.json", {"status": response.status, "expected_model_available": True})
        for case in CASES:
            folder = root / case
            ledger = folder / "author-ledger"
            with h.ManagerService(ledger, port=0) as service:
                endpoint = "http://%s:%s" % service.address
                if case in REPLAYS:
                    packet_payload = {"issue_id": case, **h.read(folder / "replay-payload.json")}
                    receipt = h.WorkflowClient(endpoint, h.token(ledger, "trial-author")).submit_field_packet(packet_payload,
                        request_id="v11-replay-" + case, idempotency_key="v11-replay-" + case)
                    h.write(folder / "host-replay-receipt.json", receipt)
                else:
                    author_folder = folder / "author"
                    prompt = (root / "EXPERIMENTER_ROLE_CARD.md").read_text(encoding="utf-8") + "\n\n" + (root / "HANDOFF_CONTRACT.md").read_text(encoding="utf-8").split("## 整理与维护")[0]
                    prompt += "\n\n本轮只完成本项交接，调用 submit_field_packet 并核对 received。宿主已执行的材料如下，不含主持人预期图：\n" + json.dumps(h.read(folder / "dossier.json"), ensure_ascii=False, indent=2)
                    print("MODEL_START " + case + "/author", flush=True)
                    outcome = await h.model_session(root, author_folder, prompt, h.safe_env(endpoint, h.token(ledger, "trial-author"), case, "submit", author_folder, []), key)
                    sessions.append({"case": case, "role": "author", **outcome})
                    h.write(root / "sessions.json", sessions)
                    print("MODEL_DONE " + case + "/author " + json.dumps(outcome), flush=True)
                client = h.WorkflowClient(endpoint, h.token(ledger, "trial-reader"))
                packets = client.list_field_packets(case)
                h.write(folder / "author-packets.json", packets)
                entries = packets.get("items", packets.get("packets", []))
                if len(entries) != 1:
                    print("PACKET_MISSING " + case, flush=True)
                    continue
                pid = entries[0]["packet_id"]
                h.write(folder / "packet.json", client.field_packet(pid))
            for repetition in range(1, (1 if case in REPLAYS else 2) + 1):
                session_folder = folder / f"curator_{repetition}"
                session_folder.mkdir()
                replica = session_folder / "ledger"
                shutil.copytree(ledger, replica)
                with h.ManagerService(replica, port=0) as service:
                    endpoint = "http://%s:%s" % service.address
                    prompt = (root / "CURATOR_ROLE_CARD.md").read_text(encoding="utf-8")
                    prompt += "\n\n本轮仅整理 Issue " + case + " 的已释放 packet " + pid + "。读取正文，按局部工作直接逐项保存，使用实际引用；不另生成论证清单或整图再转写，不复算。共同条件、作者依据和判断需可维护。写前核对实际参数，写后回读保存记录；完成 record_field_review，报告真实引用及具体缺口。你没有实验员聊天、其他整理员或主持人评分。以下是宿主绑定的既有贡献，packet 中如采用或反驳它们，可使用真实 ID：\n" + json.dumps(h.read(folder / "prior.json"), ensure_ascii=False)
                    print("MODEL_START " + case + f"/curator_{repetition}", flush=True)
                    outcome = await h.model_session(root, session_folder, prompt, h.safe_env(endpoint, h.token(replica, "trial-curator"), case, "curate", session_folder, [pid]), key)
                    sessions.append({"case": case, "role": f"curator_{repetition}", **outcome})
                    h.write(root / "sessions.json", sessions)
                    trace = [json.loads(x) for x in (session_folder / "mcp-trace.jsonl").read_text(encoding="utf-8").splitlines()]
                    relation_ids = [rid for x in trace if x["tool"] == "curate_field_item" and not x["is_error"] for rid in x["result"]["relation_ids"]]
                    saved = h.readback(endpoint, h.token(replica, "trial-reader"), pid, relation_ids)
                    h.write(session_folder / "public-http-readback.json", saved)
                    h.propagation(endpoint, h.token(replica, "organizer-agent"), case, saved, session_folder)
                    print("MODEL_DONE " + case + f"/curator_{repetition} " + json.dumps(outcome), flush=True)
    finally:
        removed = 0
        for path in root.glob("**/credentials/*.token"):
            assert root.resolve() in path.resolve().parents
            path.unlink()
            removed += 1
        h.write(root / "cleanup.json", {"services_and_MCP_closed": True, "temporary_credentials_removed": removed,
            "provider_key_file_created": False, "sessions_started": len(sessions), "automatic_retries": 0})


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("prepare", "run"))
    parser.add_argument("--run-dir", required=True, type=Path)
    args = parser.parse_args()
    root = args.run_dir.resolve()
    if any((p / ".git").exists() for p in (root, *root.parents)):
        parser.error("Run directory must be outside source checkout")
    if args.action == "prepare":
        prepare(root)
    else:
        asyncio.run(run(root))
