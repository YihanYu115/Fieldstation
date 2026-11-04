"""Authorized finite v2 smoke trial; trusted host, artifacts outside checkout."""
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
spec = importlib.util.spec_from_file_location("handoff_host", REPO / "scripts/run_handoff_contract_trial.py")
h = importlib.util.module_from_spec(spec)
spec.loader.exec_module(h)
OLD = Path("D:/实验记录/_issue_manager_handoff_v11_trial_20261003_e106a5c9")
V1 = Path("D:/实验记录/_issue_manager_handoff_contract_trial_20261003_047ecc47")
CASES = ("U_calibration", "P_order_fix", "Z_empty")
QUESTIONS = {
    "U_calibration": "说明校准观察的输入、方法、结果和效力范围；1500 count 是否已通过验证？只改变今后的校准条件时，时间显示工作是否应被推翻？给出 UTC 16:30 的实际显示结果及范围。",
    "P_order_fix": "说明本批新旧实现的通过情况、修改解决的问题及范围；若其中一个实际用例结果被纠正，哪些判断需要重审？若今后另改验收标准，旧测试记录应如何保留？现有记录证明了性能、并发或持久化吗？",
    "Z_empty": "说明过滤输入、条件和空结果能够证明什么；今后改用另一前缀会使旧观察失效吗？说明文档检查实际确认了什么、未确认什么，以及它与过滤结果的联系。",
}
READER_TOOLS = {"list_curated_field_items", "read_field_fact", "list_field_reviews", "read_field_review"}


def initialize(ledger, case, claims):
    with closing(h.IssueManager.initialize(ledger)) as manager:
        manager.create_issue(case, "investigation", "v2 quick trial " + case)
        for actor, caps in (("trial-author", {"intake.submit"}),
                            ("trial-curator", {"context.read", "evidence.write", "evidence.relation.write"}),
                            ("trial-reader", {"context.read"})):
            manager.credentials.issue_actor(actor_id=actor, actor_kind="experiment_agent", capabilities=caps,
                maintenance_credential=manager.credentials.path_for("maintenance-agent"))
        return [manager.add_evidence(kind="report", locator=f"v2-prior:{case}/{i}",
                    description=text, issue_id=case) for i, text in enumerate(claims)]


def prepare(root):
    if root.exists():
        raise ValueError("No resets or automatic reruns")
    root.mkdir(parents=True)
    for name in ("HANDOFF_CONTRACT.md", "CURATOR_ROLE_CARD.md", "EXPERIMENTER_ROLE_CARD.md"):
        shutil.copyfile(REPO / "orchestration" / name, root / name)
    shutil.copyfile(Path(__file__), root / "controller-frozen.py")
    shutil.copyfile(REPO / "scripts/run_handoff_contract_trial.py", root / "harness-frozen.py")
    h.write(root / "plan.json", {"version": "v2", "cases": CASES, "author_sessions": 1,
        "curator_sessions": 3, "read_only_successor_sessions": 3, "wall_seconds_per_session": 300,
        "requests_per_session": 20, "tools_per_session": 35, "max_tokens_per_request": 32768,
        "model": h.MODEL, "endpoint": h.BASE, "thinking": "enabled", "reasoning_effort": "high",
        "automatic_retries": 0, "questions": QUESTIONS,
        "reader_input": "real MCP saved facts/reviews; host bounded public-HTTP relation page; no packet/dossier/raw tools",
        "comparison": "historical descriptive baseline; no randomized old-card control or success-rate estimate",
        "maintenance": "necessary result invalidation, independent-work preservation, and adding an actual future-condition run",
        "not_covered": "content/version amendment and controlled semantic repair"})
    for case in CASES:
        folder = root / case
        folder.mkdir()
        if case != "Z_empty":
            source = OLD / case if (OLD / case / "packet.json").exists() else V1 / case
            old_prior = h.read(source / "prior.json")
            prior = initialize(folder / "ledger", case, [p["description"] for p in old_prior])
            mapping = {a["evidence_id"]: b["evidence_id"] for a, b in zip(old_prior, prior)}
            packet = h.read(source / "packet.json")
            payload = {k: packet[k] for k in ("content", "attachment_refs", "sources")}
            payload["sources"] = [{k: s[k] for k in ("locator", "provided_text")} for s in payload["sources"]]
            raw = json.dumps(payload, ensure_ascii=False)
            for a, b in mapping.items():
                raw = raw.replace(a, b)
            h.write(folder / "replay-payload.json", json.loads(raw))
            h.write(folder / "replay-binding.json", {"source": str(source), "ID_mapping": mapping,
                "source_packet_sha256": hashlib.sha256((source / "packet.json").read_bytes()).hexdigest(),
                "business_text_changed": False})
        else:
            prior = initialize(folder / "ledger", case, [])
            script = '''import json,sys
from pathlib import Path
prefix=sys.argv[1]
rows=["alpha","beta"]
print(json.dumps({"fixture":"filter-v1","prefix":prefix,"inputs":rows,"matched":[x for x in rows if x.startswith(prefix)],"matching":"case-sensitive startswith","guide_exists":(Path(__file__).parent/"guide.md").is_file(),"guide_content_checked":False,"external_link_checked":False,"runs":1}))
'''
            (folder / "work.py").write_text(script, encoding="utf-8", newline="\n")
            (folder / "guide.md").write_text("# Local guide\n", encoding="utf-8", newline="\n")
            result = subprocess.run([h.sys.executable, "-I", "-X", "utf8", str(folder / "work.py"), "z"], capture_output=True, timeout=15)
            assert result.returncode == 0
            (folder / "stdout.json").write_bytes(result.stdout)
            (folder / "stderr.txt").write_bytes(result.stderr)
            h.write(folder / "dossier.json", {"task": "交接本次字符串过滤和本地文档存在检查的实际结果与限制。",
                "script_version": "filter-v1", "script_sha256": hashlib.sha256((folder / "work.py").read_bytes()).hexdigest(),
                "execution": "可信宿主本地执行一次，返回码0，无硬件或真实网络，模型无独立执行能力",
                "actual_output": json.loads(result.stdout), "actual_stderr": result.stderr.decode("utf-8"),
                "script": script, "attachments": [str(folder / n) for n in ("work.py", "stdout.json", "stderr.txt", "guide.md")]})
        h.write(folder / "prior.json", [{"evidence_id": p["evidence_id"], "description": p["description"]} for p in prior])


async def run(root):
    if (root / "run-started.json").exists():
        raise ValueError("Already started")
    key = os.environ["DEEPSEEK_API_KEY"]
    h.write(root / "run-started.json", {"time_ns": h.time.time_ns()})
    sessions = []
    try:
        with h.urlopen(h.Request(h.BASE + "/models", headers={"Authorization": "Bearer " + key}), timeout=30) as response:
            models = json.loads(response.read())
            assert h.MODEL in [x["id"] for x in models["data"]]
            h.write(root / "model-preflight.json", {"status": response.status, "expected_model_available": True})
        for case in CASES:
            folder = root / case
            ledger = folder / "ledger"
            with h.ManagerService(ledger, port=0) as service:
                endpoint = "http://%s:%s" % service.address
                if case != "Z_empty":
                    h.WorkflowClient(endpoint, h.token(ledger, "trial-author")).submit_field_packet(
                        {"issue_id": case, **h.read(folder / "replay-payload.json")},
                        request_id="v2-replay-" + case, idempotency_key="v2-replay-" + case)
                else:
                    sf = folder / "author"
                    prompt = (root / "EXPERIMENTER_ROLE_CARD.md").read_text(encoding="utf-8") + "\n" + (root / "HANDOFF_CONTRACT.md").read_text(encoding="utf-8").split("## 整理与维护")[0]
                    prompt += "\n本轮只交接宿主已执行的材料，提交并核对 received：\n" + json.dumps(h.read(folder / "dossier.json"), ensure_ascii=False)
                    print("START " + case + "/author", flush=True)
                    outcome = await h.model_session(root, sf, prompt, h.safe_env(endpoint, h.token(ledger, "trial-author"), case, "submit", sf, []), key, wall_seconds=300, request_limit=20, tool_limit=35)
                    sessions.append({"case": case, "role": "author", **outcome})
                    h.write(root / "sessions.json", sessions)
                entries = h.WorkflowClient(endpoint, h.token(ledger, "trial-reader")).list_field_packets(case)["items"]
                if len(entries) != 1:
                    raise ValueError("Expected one packet")
                pid = entries[0]["packet_id"]
                h.write(folder / "packet.json", h.WorkflowClient(endpoint, h.token(ledger, "trial-reader")).field_packet(pid))
                sf = folder / "curator"
                prompt = (root / "CURATOR_ROLE_CARD.md").read_text(encoding="utf-8") + "\n本轮整理已释放 packet " + pid + "，Issue " + case + "；直接使用现有工具，完成 review。你没有主持人评分或其他岗位聊天。既有贡献真实引用：\n" + json.dumps(h.read(folder / "prior.json"), ensure_ascii=False)
                print("START " + case + "/curator", flush=True)
                outcome = await h.model_session(root, sf, prompt, h.safe_env(endpoint, h.token(ledger, "trial-curator"), case, "curate", sf, [pid]), key, wall_seconds=300, request_limit=20, tool_limit=35)
                sessions.append({"case": case, "role": "curator", **outcome})
                h.write(root / "sessions.json", sessions)
                trace = [json.loads(line) for line in (sf / "mcp-trace.jsonl").read_text(encoding="utf-8").splitlines()]
                rids = [rid for t in trace if t["tool"] == "curate_field_item" and not t["is_error"] for rid in t["result"]["relation_ids"]]
                saved = h.readback(endpoint, h.token(ledger, "trial-reader"), pid, rids)
                h.write(sf / "public-http-readback.json", saved)
                relations = [{k: r[k] for k in ("source_evidence_id", "target_evidence_id", "relation_type", "rationale", "binding_current")} for r in saved["relations"].values()]
                assert len(json.dumps(relations, ensure_ascii=False).encode("utf-8")) <= 16384
                reader_folder = folder / "successor"
                prompt = "你是无历史聊天的只读维护接手者。仅从真实入账记录回答下列维护问题，每个回答给出采用的 fact_ref 或 Evidence ID、条件、范围及具体信息缺口。不要补新研究，不把 review 当通过证书。不能读取原始 packet、实验员交接或执行 dossier；可用工具读取已保存贡献和 review。\npacket_id=" + pid + "\n任务：" + QUESTIONS[case] + "\n宿主通过公开HTTP获取的已保存关系页（没有预期答案）：\n" + json.dumps(relations, ensure_ascii=False) + "\n既有记录：" + json.dumps(h.read(folder / "prior.json"), ensure_ascii=False)
                print("START " + case + "/successor", flush=True)
                outcome = await h.model_session(root, reader_folder, prompt, h.safe_env(endpoint, h.token(ledger, "trial-reader"), case, "read", reader_folder, [pid]), key, wall_seconds=300, request_limit=20, tool_limit=35, tool_names=READER_TOOLS)
                sessions.append({"case": case, "role": "successor", **outcome})
                h.write(root / "sessions.json", sessions)
                h.propagation(endpoint, h.token(ledger, "organizer-agent"), case, saved, sf)
                if case == "Z_empty":
                    before = h.preview(endpoint, h.token(ledger, "organizer-agent"), case, [f["mapping"]["evidence_id"] for f in saved["facts"]])
                    result = subprocess.run([h.sys.executable, "-I", "-X", "utf8", str(folder / "work.py"), "a"], capture_output=True, timeout=15)
                    assert result.returncode == 0
                    event = h.http(endpoint, h.token(ledger, "organizer-agent"), "POST", "/v1/scoped-evidence-contributions",
                        {"issue_id": case, "kind": "observation", "source": "v2-host-new-condition-run", "description": "宿主另一次执行，未来前缀改为a：" + result.stdout.decode("utf-8"), "reason": "不同条件的新观察，不改旧观察", "related_evidence": []})
                    after = h.preview(endpoint, h.token(ledger, "organizer-agent"), case, [f["mapping"]["evidence_id"] for f in saved["facts"]])
                    h.write(folder / "future-condition-probe.json", {"actual_new_output": json.loads(result.stdout), "new_event": event, "before": before, "after": after})
                print("DONE " + case, flush=True)
    finally:
        count = 0
        for p in root.glob("**/credentials/*.token"):
            assert root.resolve() in p.resolve().parents
            p.unlink()
            count += 1
        h.write(root / "cleanup.json", {"services_closed": True, "mcp_closed": True, "temporary_credentials_removed": count, "provider_key_file_created": False})


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("prepare", "run"))
    parser.add_argument("--run-dir", required=True, type=Path)
    args = parser.parse_args()
    root = args.run_dir.resolve()
    if any((p / ".git").exists() for p in (root, *root.parents)):
        parser.error("Run directory must be outside checkout")
    if args.action == "prepare":
        prepare(root)
    else:
        asyncio.run(run(root))
