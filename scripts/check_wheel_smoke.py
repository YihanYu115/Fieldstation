"""Verify the installed kernel's single-rule fresh-project contract."""
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
import tempfile
import venv
from pathlib import Path

PROBE = r'''import json, sys, urllib.request
from pathlib import Path
from contextlib import closing
import issue_manager
from issue_manager import IssueManager
from issue_manager.schema import SCHEMA_VERSION
from issue_manager.context_scoped_rule import scoped_v2_rule_id
from issue_manager.manager_api import ManagerService
import project_package
root = Path(sys.argv[1])
with closing(IssueManager.initialize(root / "ledger")) as manager:
    rules = manager.context_rules.describe()
    assert rules["supported_rule_ids"] == [scoped_v2_rule_id()]
    assert rules["runtime_matches_active"]
    assert len(manager.store.rows("SELECT * FROM context_rule_versions")) == 1
    manager.create_issue("scope", "investigation", "Installed kernel")
    evidence = manager.add_evidence(kind="external", locator="urn:installed:observation", issue_id="scope")["evidence_id"]
    package = manager.context_maintenance.prepare("scope", evidence_ids=[evidence])
    assert package["actual_input"]["materials"]["support_ids"] == [evidence]
    assert manager.doctor()["ok"]
    token = json.loads(manager.credentials.path_for("organizer-agent").read_text(encoding="utf-8"))["token"]
    with ManagerService(root / "ledger", port=0) as service:
        endpoint = "http://%s:%s" % service.address
        body = {"root_issue_id": "scope", "contract_id": "installed", "expected_revision": 0,
                "reason": "Synthetic installed HTTP acceptance", "document": {
                    "reference_prefix": "synthetic:", "summary": "Installed reader",
                    "capability": "synthetic.read", "parameters": "reference and part",
                    "example": "reference=synthetic:1; part=body", "semantics": "Complete requested part; no hash",
                    "failures": "Missing binding: request host capability", "change_impact": "initial",
                    "impact_note": "Synthetic program test only"}}
        request = urllib.request.Request(endpoint + "/v1/original-access", data=json.dumps(body).encode(),
            headers={"Authorization": "Bearer " + token, "Content-Type": "application/json",
                     "X-Request-ID": "installed-access", "Idempotency-Key": "installed-access"})
        with urllib.request.urlopen(request) as response:
            assert json.load(response)["result"]["revision"] == 1
        request = urllib.request.Request(endpoint + "/v1/original-access/read?issue_id=scope&contract_id=installed&revision=1",
            headers={"Authorization": "Bearer " + token})
        with urllib.request.urlopen(request) as response:
            assert json.load(response)["result"]["document"] == body["document"]
        admission = {"issue_id": "scope", "kind": "observation", "source": "synthetic:1",
                     "description": "Synthetic pinned observation", "reason": "Installed binding check",
                     "related_evidence": []}
        request = urllib.request.Request(endpoint + "/v1/scoped-evidence-contributions", data=json.dumps(admission).encode(),
            headers={"Authorization": "Bearer " + token, "Content-Type": "application/json",
                     "X-Request-ID": "installed-pin", "Idempotency-Key": "installed-pin"})
        with urllib.request.urlopen(request) as response:
            saved = json.load(response)["result"]["evidence"]
            assert saved["original_access"][0]["revision"] == 1
        request = urllib.request.Request(endpoint + "/v1/original-access/read?issue_id=scope&evidence_id=" + saved["evidence_id"],
            headers={"Authorization": "Bearer " + token})
        with urllib.request.urlopen(request) as response:
            assert json.load(response)["result"]["revision"] == 1
    contracts = json.loads(Path(project_package.__file__).with_name("contracts.json").read_text(encoding="utf-8"))
    assert contracts["$defs"]["imComponentManifest"]["properties"]["schema_version"]["const"] == SCHEMA_VERSION
    assert contracts["$defs"]["projectManifest"]["properties"]["components"]["properties"]["im"]["properties"]["schema_version"]["const"] == SCHEMA_VERSION
    result = {"installed_version": issue_manager.__version__,
              "schema_version": manager.store._schema_version(manager.store.conn),
              "module_path": str(Path(issue_manager.__file__).resolve()),
              "scoped_v2_verified": True, "single_rule_verified": True}
    result["original_access_http_verified"] = True
    result["automatic_original_access_pin_verified"] = True
with closing(IssueManager(root / "ledger")) as reopened:
    assert reopened.context_rules.describe()["runtime_matches_active"]
print(json.dumps(result))
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("wheel", type=Path)
    parser.add_argument("--expected-version", default="0.9.0rc11")
    parser.add_argument("--expected-schema-version", type=int, default=10)
    parser.add_argument("--receipt-out", type=Path)
    args = parser.parse_args()
    wheel = args.wheel.resolve()
    with tempfile.TemporaryDirectory(prefix="im-wheel-") as directory:
        root = Path(directory)
        venv.EnvBuilder(with_pip=True).create(root / "venv")
        python = root / "venv" / ("Scripts/python.exe" if sys.platform == "win32" else "bin/python")
        subprocess.run([str(python), "-m", "pip", "install", "--no-deps", str(wheel)], check=True, capture_output=True)
        result = subprocess.run([str(python), "-I", "-X", "utf8", "-c", PROBE, str(root)],
                                cwd=root, capture_output=True, text=True, encoding="utf-8")
        if result.returncode:
            raise RuntimeError(result.stderr)
        receipt = json.loads(result.stdout)
        assert receipt["installed_version"] == args.expected_version
        assert receipt["schema_version"] == args.expected_schema_version
        assert root in Path(receipt["module_path"]).parents
        help_result = subprocess.run([str(python), "-I", "-m", "issue_manager", "--help"],
                                     cwd=root, capture_output=True, text=True, encoding="utf-8", check=True)
        assert "migrate" not in help_result.stdout
        receipt.update(wheel=wheel.name, wheel_sha256=hashlib.sha256(wheel.read_bytes()).hexdigest(),
                       repository_import_excluded=True)
        output = json.dumps(receipt, ensure_ascii=False, indent=2) + "\n"
        if args.receipt_out:
            args.receipt_out.parent.mkdir(parents=True, exist_ok=True)
            args.receipt_out.write_text(output, encoding="utf-8")
        print(output)


if __name__ == "__main__":
    main()
