"""Install one orchestration wheel and verify the sole registered professional chain."""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import venv
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("wheel", type=Path)
    parser.add_argument("packages", type=Path, help="Generated registered professional packages")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    root = args.output.resolve()
    if root.exists() or root.is_relative_to(Path(__file__).resolve().parents[1]):
        parser.error("output must be a new external directory")
    root.mkdir(parents=True)
    venv.EnvBuilder(with_pip=True).create(root / "venv")
    python = root / "venv" / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    installed = subprocess.run([str(python), "-m", "pip", "install", str(args.wheel.resolve(strict=True)) + "[mcp]"],
        capture_output=True, text=True, encoding="utf-8", timeout=180)
    (root / "install.log").write_text(installed.stdout + installed.stderr, encoding="utf-8")
    if installed.returncode:
        raise SystemExit("Wheel installation failed; inspect " + str(root / "install.log"))
    result = subprocess.run([sys.executable, str(Path(__file__).with_name("check_registered_professional_install.py")),
        "--python", str(python), "--packages", str(args.packages.resolve(strict=True)), "--output", str(root / "program")],
        capture_output=True, text=True, encoding="utf-8", timeout=330)
    (root / "program.log").write_text(result.stdout + result.stderr, encoding="utf-8")
    if result.returncode:
        raise SystemExit("Registered installation failed; inspect " + str(root / "program.log"))
    report = json.loads(result.stdout.strip().splitlines()[-1])
    (root / "report.json").write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False))


if __name__ == "__main__":
    main()
