"""
Blast-radius policy gate for CI.

Fails a build when a dependency's structural exposure crosses a threshold you
set, so the number this tool produces can block a merge instead of sitting in a
dashboard nobody opens.

    python gate.py --package ms                      # report only
    python gate.py --package ms --max-apps 10        # fail if it reaches >10 apps
    python gate.py --package ms --max-exposure 15    # fail above 15% of the portfolio
    python gate.py --worst 5 --max-exposure 20       # audit the riskiest packages
    python gate.py --package ms --json               # machine-readable

Exit codes: 0 within policy, 1 policy breached, 2 could not run.
"""
from __future__ import annotations

import argparse
import json
import os
import sys

from engine import (GraphError, bump_patch, detonate, load_graph, node_name,
                    node_version, nodes_named, rank_critical, rank_mitigations)


def _resolve_targets(G, spec):
    """Accept 'lodash', 'npm:lodash@4.17.21', or 'lodash@4.17.21'."""
    if spec in G:
        return [spec]
    if spec.startswith("npm:"):
        spec = spec[4:]
    if "@" in spec.lstrip("@"):
        head, _, version = spec.rpartition("@")
        candidate = f"npm:{head}@{version}"
        if candidate in G:
            return [candidate]
    found = nodes_named(G, spec)
    return found


def evaluate(G, app_roots, targets, scenario, budget):
    versions = ({t: bump_patch(node_version(G, t)) for t in targets}
                if scenario == "future" else None)
    result = detonate(G, app_roots, targets, versions)
    if result is None:
        return None
    mitigation = rank_mitigations(G, app_roots, result, budget=budget) if budget else None
    return result, mitigation


def main():
    parser = argparse.ArgumentParser(description="Blast-radius policy gate.")
    parser.add_argument("--package", help="package name, or name@version")
    parser.add_argument("--worst", type=int, metavar="N",
                        help="check the N most structurally critical packages instead")
    parser.add_argument("--max-apps", type=int, default=None,
                        help="fail if more applications than this are exposed")
    parser.add_argument("--max-exposure", type=float, default=None,
                        help="fail above this percentage of the portfolio")
    parser.add_argument("--scenario", choices=("future", "resident"), default="future",
                        help="future: attacker publishes a new release (default). "
                             "resident: the version already in the tree is malicious.")
    parser.add_argument("--budget", type=int, default=3,
                        help="how many upgrades to propose (0 to skip)")
    parser.add_argument("--graph", default="graph.json")
    parser.add_argument("--json", action="store_true", help="emit JSON")
    args = parser.parse_args()

    if not args.package and not args.worst:
        parser.error("give either --package or --worst")

    try:
        G, app_roots = load_graph(args.graph)
    except GraphError as exc:
        # exit 2, never 1: a damaged corpus is a broken tool, not a policy breach,
        # and CI must be able to tell those apart.
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(2)
    if G is None:
        print(f"ERROR: {args.graph} not found. Run: python build.py", file=sys.stderr)
        sys.exit(2)

    checks = []
    if args.package:
        targets = _resolve_targets(G, args.package)
        if not targets:
            print(f"ERROR: '{args.package}' is not in this corpus.", file=sys.stderr)
            sys.exit(2)
        checks.append((node_name(G, targets[0]), targets))
    if args.worst:
        for row in rank_critical(G, app_roots, scope="name", limit=args.worst):
            checks.append((row["name"], row["ids"]))

    total = max(len(app_roots), 1)
    report, breached = [], False

    for label, targets in checks:
        evaluated = evaluate(G, app_roots, targets, args.scenario, args.budget)
        if evaluated is None:
            continue
        result, mitigation = evaluated
        exposure = result["exposure_pct"]
        exposed = len(result["affected_apps"])

        failed = []
        if args.max_apps is not None and exposed > args.max_apps:
            failed.append(f"{exposed} applications exposed (limit {args.max_apps})")
        if args.max_exposure is not None and exposure > args.max_exposure:
            failed.append(f"{exposure}% exposure (limit {args.max_exposure}%)")
        breached = breached or bool(failed)

        entry = {
            "package": label,
            "targets": targets,
            "scenario": result["scenario"],
            "applications_exposed": exposed,
            "applications_total": total,
            "exposure_pct": exposure,
            "applications_shielded": len(result["shielded_apps"]),
            "packages_reached": len(result["reached"]),
            "max_hops": result["max_hops"],
            "status": "FAIL" if failed else "PASS",
            "violations": failed,
        }
        if mitigation:
            entry["recommended_upgrades"] = [
                {"package": f"{f['name']}@{f['version']}", "applications_saved": f["apps_saved"]}
                for f in mitigation["fixes"]
            ]
            entry["exposure_after_upgrades"] = mitigation["apps_after"]
        report.append(entry)

    if args.json:
        print(json.dumps({"results": report, "status": "FAIL" if breached else "PASS"},
                         indent=2))
    else:
        for entry in report:
            mark = "FAIL" if entry["status"] == "FAIL" else "ok"
            print(f"[{mark:>4}] {entry['package']}: "
                  f"{entry['applications_exposed']}/{entry['applications_total']} "
                  f"applications ({entry['exposure_pct']}%), "
                  f"{entry['applications_shielded']} shielded by pins, "
                  f"{entry['max_hops']} hop(s)")
            for violation in entry["violations"]:
                print(f"         policy: {violation}")
            for upgrade in entry.get("recommended_upgrades", []):
                print(f"         upgrade {upgrade['package']} "
                      f"-> saves {upgrade['applications_saved']} application(s)")
        if not report:
            print("nothing to check")
        print("\n" + ("POLICY BREACHED" if breached else "within policy"))

    sys.exit(1 if breached else 0)


if __name__ == "__main__":
    main()
