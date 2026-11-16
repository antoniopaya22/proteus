"""The reproduction script names only modules, detectors and stages that exist."""

import importlib
import os
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _dry(*stages: str) -> str:
    r = subprocess.run(["bash", "scripts/reproduce.sh", *stages], cwd=ROOT, text=True,
                       env={**os.environ, "DRY": "1"}, capture_output=True, check=False)
    assert r.returncode == 0, r.stderr[-2000:]
    return r.stderr


def test_dry_run_prints_every_stage():
    out = _dry("all")
    script = (ROOT / "scripts/reproduce.sh").read_text()
    stages = re.search(r'^STAGES="([^"]+)"', script, re.MULTILINE).group(1).split()
    assert stages == re.findall(r"^stage_(\w+)\(\)", script, re.MULTILINE)
    assert len(out.splitlines()) > 90 and "paper_tables.sh" in out


def script_models() -> set[str]:
    """Detector names that the script passes to h1 (parts of ``a&b``, without ``-K``)."""
    names = set()
    for line in _dry("all").splitlines():
        m = re.search(r"--models ((?:\w[\w&-]* ?)+?)(?= --| >)", line)
        if m and "evaluation.h1" in line and "PROTEUS_EVIDENCE=v1" not in line:
            names |= {re.sub(r"-\d+$", "", part) for n in m.group(1).split() for part in n.split("&")}
    return names


def test_commands_name_existing_modules():
    modules = set(re.findall(r"-m (proteus\.[\w.]+)", _dry("all")))
    assert len(modules) > 12
    for m in modules:
        importlib.import_module(m)
    # That the detectors exist is checked in test_end_to_end, which has real evidence.
    assert {"proteus", "proteus_cert_r", "proteus2", "apollon", "kitnet_local"} <= script_models()
