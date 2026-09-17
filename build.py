"""
Step 2: turn the downloaded records into one graph and precompute the rankings.

    python build.py

Writes graph.json (the corpus) and critical.json (the criticality rankings, at
both package-version and package-name scope). Nothing here touches the network.
"""
from __future__ import annotations

import json
import os
import sys
import time

from engine import (SCOPE_NAME, SCOPE_VERSION, build_graph, rank_critical,
                    save_graph)

RECORDS = "records.json"
CRITICAL = "critical.json"


def main():
    if not os.path.exists(RECORDS):
        print(f"ERROR: {RECORDS} missing. Run: python fetch.py")
        sys.exit(1)

    with open(RECORDS, "r", encoding="utf-8") as f:
        records = json.load(f)

    G, app_roots = build_graph(records)
    if not app_roots:
        print("ERROR: no applications in records.json - nothing to analyse.")
        sys.exit(1)

    print(f"Applications      : {len(app_roots):,}")
    print(f"Package-versions  : {G.number_of_nodes():,}")
    print(f"Dependency edges  : {G.number_of_edges():,}")
    print(f"Distinct packages : {len({d.get('name') for _, d in G.nodes(data=True)}):,}")

    print("\nMost depended-upon packages (sanity check - you should recognise these):")
    for node, degree in sorted(G.in_degree, key=lambda x: -x[1])[:10]:
        print(f"  {degree:5}  {node}")

    save_graph(G, app_roots)
    print(f"\nSaved graph.json ({os.path.getsize('graph.json') / 1e6:.1f} MB)")

    rankings = {}
    for scope, label in ((SCOPE_NAME, "package"), (SCOPE_VERSION, "package-version")):
        started = time.time()
        print(f"\nRanking blast radius at {label} scope...")
        rankings[scope] = rank_critical(G, app_roots, scope=scope, limit=40)
        print(f"  {len(rankings[scope])} ranked in {time.time() - started:.1f}s")
        print(f"  {'apps':>5} {'now':>5}  {'held':>5}  package")
        for row in rankings[scope][:8]:
            print(f"  {row['apps']:5} {row['apps_now']:5}  {row['held_back']:5}  "
                  f"{row['name']} ({row['exposure_pct']}% exposure)")

    with open(CRITICAL, "w", encoding="utf-8") as f:
        json.dump({
            "generated": time.strftime("%Y-%m-%d %H:%M"),
            "applications": len(app_roots),
            "packages": G.number_of_nodes(),
            "edges": G.number_of_edges(),
            "rankings": rankings,
        }, f)

    print("\n'apps' is the future-release scenario (an attacker publishes a new "
          "version).\n'now' is the lockfile-resident scenario (the version already "
          "in your tree).\n'held' is how many applications version pins are "
          "currently holding back.")
    print("\nNext: streamlit run app.py")


if __name__ == "__main__":
    main()
