"""Compliance evidence. Before: screenshot 50 consoles. After: collect, hash and map evidence to controls."""
from __future__ import annotations

import datetime as dt
import hashlib
import json
from pathlib import Path

import yaml


def _select(items: list[dict], where: dict | None) -> list[dict]:
    if not where:
        return items
    return [i for i in items if all(i.get(k) == v for k, v in where.items())]


def _ok(item: dict, rule: dict) -> bool:
    value = item.get(rule["field"])
    if "equals" in rule:
        return value == rule["equals"]
    if "max" in rule:
        return value is not None and value <= rule["max"]
    raise ValueError(f"unsupported rule {rule}")


def evaluate(control: dict, snapshot: dict) -> tuple[bool, list[str]]:
    check = control["check"]
    items = _select(snapshot.get(check["path"], []), check.get("where"))
    if not items:
        return False, ["no matching evidence found"]
    if "all" in check:
        bad = [i for i in items if not _ok(i, check["all"])]
        return not bad, [json.dumps(b) for b in bad]
    bad = [i for i in items if not _ok(i, check)]
    return not bad, [json.dumps(b) for b in bad]


def collect(controls_path: Path, snapshots_dir: Path) -> dict:
    controls = yaml.safe_load(Path(controls_path).read_text())["controls"]
    results, hashes = [], {}
    for c in controls:
        f = Path(snapshots_dir) / c["evidence"]
        raw = f.read_bytes()
        hashes[c["evidence"]] = hashlib.sha256(raw).hexdigest()
        passed, failures = evaluate(c, json.loads(raw))
        results.append({"id": c["id"], "title": c["title"], "frameworks": c["frameworks"], "evidence": c["evidence"],
                        "sha256": hashes[c["evidence"]], "passed": passed, "failures": failures})
    return {"collected_at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"), "results": results}


def report(pack: dict) -> str:
    res = pack["results"]
    lines = ["# Compliance evidence pack", "",
             f"Collected {pack['collected_at']} · {sum(r['passed'] for r in res)}/{len(res)} controls passing", "",
             "| | Control | SOC 2 | ISO 27001 | NIST CSF | Evidence (sha256) | Exceptions |", "|---|---|---|---|---|---|---|"]
    for r in res:
        fw = r["frameworks"]
        exc = "<br>".join(r["failures"]).replace("|", "/") or ""
        lines.append(f"| {'✅' if r['passed'] else '❌'} | {r['title']} | {fw.get('SOC2', '')} | {fw.get('ISO27001', '')} | "
                     f"{fw.get('NIST_CSF', '')} | `{r['evidence']}` `{r['sha256'][:12]}` | {exc} |")
    lines += ["", "_Evidence files are hashed at collection time so auditors can verify they were not altered._"]
    return "\n".join(lines) + "\n"
