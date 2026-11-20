"""sanity: AI carries the volume, you keep the judgment.

  python -m sanity demo                                     # the whole loop on a synthetic SOC day
  python -m sanity run      --alerts alerts.jsonl           # signals -> triage -> enrich -> AI summary -> queue
  python -m sanity queue                                    # what needs a human today
  python -m sanity decide   malware:payroll-db-01 approve --by alice
  python -m sanity decide   data_exfiltration:s.kim reject --by alice --reason "false positive: approved OneDrive sync"
  python -m sanity act                                      # runs approved actions only (dry-run executors)
  python -m sanity incident INC-001 --chat chat.jsonl       # timeline + summary from logs and chat
  python -m sanity evidence --snapshots evidence-snapshots/ # controls -> SOC 2 / ISO 27001 / NIST CSF
  python -m sanity audit                                    # verify the hash-chained audit log
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import decisions, evidence, incident, samples
from .assistant import LLMAssistant
from .loop import CONFIG, run
from .store import Store
from .triage import load_yaml


def _assistant(args):
    return LLMAssistant(load_yaml(CONFIG / "ai.yaml")) if getattr(args, "llm", False) else None


def print_queue(queue: list[dict]) -> None:
    print(f"\n{'':2}{'Incident':<9}{'Score':>6}  {'Severity':<9}{'Key':<38}Proposed (needs approval)")
    for q in queue:
        flag = " ⚠ " + q["flags"][0].split(":")[0] if q["flags"] else ""
        print(f"  {q['id']:<9}{q['score']:>6}  {q['severity']:<9}{q['key']:<38}{', '.join(q['proposed_actions'])}{flag}")


def cmd_run(args) -> int:
    res = run(Path(args.alerts), Store(args.state), _assistant(args))
    m = res["metrics"]
    print(f"{m['alerts']:,} alerts → {m['groups']} groups → {m['suppressed_alerts']:,} suppressed as known noise → "
          f"{m['incidents']} incidents → {m['for_review']} for human review")
    print_queue(res["queue"])
    return 0


def cmd_queue(args) -> int:
    print_queue(Store(args.state).load("queue.json", []))
    return 0


def cmd_decide(args) -> int:
    acts = args.actions.split(",") if args.actions else None
    d = decisions.decide(Store(args.state), args.key, args.verdict, args.by, acts, args.reason or "")
    print(json.dumps(d, indent=2))
    return 0


def cmd_act(args) -> int:
    for r in decisions.act(Store(args.state), load_yaml(CONFIG / "actions.yaml")):
        print(f"{r['incident']} {r['action']}: {r['result']} (approved by {r['approved_by']})")
    return 0


def cmd_incident(args) -> int:
    store = Store(args.state)
    res = run(Path(args.alerts), store) if args.alerts else None
    incs = {i.id: i for i in (res["incidents"] if res else [])}
    if args.id not in incs:
        print(f"{args.id} not found; pass --alerts to rebuild the incident list")
        return 2
    md = incident.report(incs[args.id], incident.load_chat(Path(args.chat)) if args.chat else [], store)
    if args.out:
        Path(args.out).write_text(md)
    print(md)
    return 0


def cmd_evidence(args) -> int:
    pack = evidence.collect(Path(args.controls), Path(args.snapshots))
    md = evidence.report(pack)
    if args.out:
        Path(args.out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.out).write_text(md)
        Path(args.out).with_suffix(".json").write_text(json.dumps(pack, indent=2))
    print(md)
    return 0


def cmd_audit(args) -> int:
    store = Store(args.state)
    recs = store.audit_records()
    ok = store.verify_audit_chain()
    for r in recs[-args.tail:]:
        print(f"{r['ts']}  {r['actor']:<24} {r['event']:<16} {json.dumps(r['details'])[:110]}")
    print(f"\n{len(recs)} records · hash chain {'INTACT' if ok else 'BROKEN'}")
    return 0 if ok else 1


def cmd_demo(args) -> int:
    out = Path(args.out)
    data = samples.write(out / "data")
    store = Store(out / "state")
    catalog = load_yaml(CONFIG / "actions.yaml")
    say = lambda s: print(f"\n=== {s} ===")  # noqa: E731

    say("1. Signals → AI triage → AI enrich (run 1)")
    first = run(data / "alerts.jsonl", store)
    m1 = first["metrics"]
    print(f"{m1['alerts']:,} open alerts → {m1['suppressed_alerts']:,} suppressed as known noise → "
          f"{m1['incidents']} incidents → top {m1['for_review']} for you ({m1['alerts_behind_review']} alerts behind them)")
    print_queue(first["queue"])
    top = first["queue"][0]
    print(f"\n{top['id']} AI summary: {top['summary']['what_happened']}\n  Why it matters: {top['summary']['why_it_matters']}")
    if top["flags"]:
        print(f"  ⚠ Prompt injection found inside the alert data. Treated as data; the verdict and actions were not changed.")

    say("2. Guardrail: the AI tries to act on its own")
    try:
        decisions.ai_execute(store, "isolate_host", "payroll-db-01", catalog)
    except decisions.ApprovalRequired as err:
        print(f"REFUSED: {err}")
    try:
        decisions.decide(store, top["key"], "approve", by="ai:assistant")
    except decisions.ApprovalRequired as err:
        print(f"REFUSED: {err}")

    say("3. Human decision")
    q = {x["key"]: x for x in first["queue"]}
    for key, verdict, reason in [
        ("malware:payroll-db-01", "approve", "confirmed C2 beaconing"),
        ("data_exposure:stg-customer-exports", "approve", "customer PII publicly readable"),
        ("account_compromise:j.admin", "approve", "MFA fatigue followed by approved prompt"),
        ("data_exfiltration:s.kim", "reject", "false positive: approved OneDrive sync for a laptop migration"),
        ("phishing:mailbox:cfo", "escalate", "send to the email security team"),
    ]:
        if key in q:
            d = decisions.decide(store, key, verdict, by="alice.analyst", reason=reason)
            print(f"{d['incident']:<8} {verdict.upper():<9} {key:<38} {reason}")

    say("4. Act: only approved actions, each with its own scoped credential (dry-run)")
    for r in decisions.act(store, catalog):
        print(f"{r['incident']:<8} {r['result']}")

    say("5. Learn: the rejected false positive tunes the next run")
    for s in decisions.load_learned(store):
        print(f"{s['id']} suppress {s['match']} until {s['expires']} (owner {s['owner']})")
    second = run(data / "alerts.jsonl", store)
    gone = set(q) - {x["key"] for x in second["queue"]}
    new = {x["key"] for x in second["queue"]} - set(q)
    print(f"run 2: {second['metrics']['suppressed_alerts']:,} suppressed (was {m1['suppressed_alerts']:,}); "
          f"dropped from queue: {', '.join(sorted(gone)) or 'none'}; newly surfaced: {', '.join(sorted(new)) or 'none'}")

    say("6. Incident summary from logs + chat (secrets redacted)")
    inc = next(i for i in first["incidents"] if i.entities[0] == "payroll-db-01")
    md = incident.report(inc, incident.load_chat(data / "incident-chat.jsonl"), store)
    (out / "incident-INC-001.md").write_text(md)
    print("\n".join(md.splitlines()[:22]))

    say("7. Compliance evidence mapped to controls")
    pack = evidence.collect(CONFIG / "controls.yaml", data / "evidence-snapshots")
    (out / "evidence-pack.md").write_text(evidence.report(pack))
    (out / "evidence-pack.json").write_text(json.dumps(pack, indent=2))
    for r in pack["results"]:
        print(f"{'PASS' if r['passed'] else 'FAIL'}  {r['id']:<16} {r['title']:<52} SOC2 {r['frameworks']['SOC2']}")

    say("8. Audit trail")
    print(f"{len(store.audit_records())} audit records · hash chain {'INTACT' if store.verify_audit_chain() else 'BROKEN'}")

    say("The outcome")
    m2 = second["metrics"]
    rows = [("Alerts you read", f"{m1['alerts']:,} (all of them)", f"{m2['for_review']} incidents, ranked, with context"),
            ("Noise filtered", "by hand", f"{m2['suppressed_alerts']:,} alerts, every rule owned and expiring"),
            ("Timeline at 4 a.m.", "written by hand", "drafted from logs and chat"),
            ("Audit evidence", "screenshots", f"{len(pack['results'])} controls hashed and mapped"),
            ("Who decides", "you", "still you. AI suggests, it never acts alone")]
    print(f"{'':20}{'Before':<24}With AI + guardrails")
    for a, b, c in rows:
        print(f"{a:<20}{b:<24}{c}")
    print(f"\nReports written to {out}/")
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="sanity", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--state", default=".sanity", help="state directory (queue, decisions, audit log)")
    sub = p.add_subparsers(dest="cmd", required=True)
    d = sub.add_parser("demo")
    d.add_argument("--out", default="demo-out")
    d.set_defaults(fn=cmd_demo)
    r = sub.add_parser("run")
    r.add_argument("--alerts", required=True)
    r.add_argument("--llm", action="store_true", help="use an approved model via an OpenAI-compatible API")
    r.set_defaults(fn=cmd_run)
    sub.add_parser("queue").set_defaults(fn=cmd_queue)
    c = sub.add_parser("decide")
    c.add_argument("key")
    c.add_argument("verdict", choices=sorted(decisions.VERDICTS))
    c.add_argument("--by", required=True)
    c.add_argument("--actions")
    c.add_argument("--reason")
    c.set_defaults(fn=cmd_decide)
    sub.add_parser("act").set_defaults(fn=cmd_act)
    i = sub.add_parser("incident")
    i.add_argument("id")
    i.add_argument("--alerts")
    i.add_argument("--chat")
    i.add_argument("--out")
    i.set_defaults(fn=cmd_incident)
    e = sub.add_parser("evidence")
    e.add_argument("--snapshots", required=True)
    e.add_argument("--controls", default=str(CONFIG / "controls.yaml"))
    e.add_argument("--out")
    e.set_defaults(fn=cmd_evidence)
    a = sub.add_parser("audit")
    a.add_argument("--tail", type=int, default=15)
    a.set_defaults(fn=cmd_audit)
    args = p.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
