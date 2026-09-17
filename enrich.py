"""
Optional step: add two things the dependency graph alone cannot tell you.

    python enrich.py

1. Known vulnerabilities, from OSV.dev. Plotting CVSS severity against blast
   radius is the argument this whole project makes, drawn rather than asserted:
   the interesting quadrant is low severity, high blast radius.

2. Maintainer count, from the npm registry. Structural criticality says how far
   a compromise spreads; maintainer count says how hard it is to start one. A
   widely-depended-upon package with a single maintainer is the event-stream
   story, and neither number finds it alone.

Writes enrich.json. The interface works without it and simply hides the panels,
so this step is always safe to skip.
"""
from __future__ import annotations

import json
import os
import sqlite3
import sys
import time
import urllib.error
import urllib.request
from urllib.parse import quote

from engine import GraphError, load_graph, node_name, node_version

OSV_BATCH = "https://api.osv.dev/v1/querybatch"
OSV_VULN = "https://api.osv.dev/v1/vulns/"
NPM_SEARCH = "https://registry.npmjs.org/-/v1/search"
NPM_REGISTRY = "https://registry.npmjs.org"
DB = "cache.db"
OUT = "enrich.json"
CRITICAL = "critical.json"
PAUSE = 0.1
BATCH = 100
MAX_VULN_DETAILS = 120


def db():
    con = sqlite3.connect(DB)
    con.execute("CREATE TABLE IF NOT EXISTS cache2 ("
                "url TEXT PRIMARY KEY, status INTEGER, body TEXT)")
    return con


def cached_get(con, url):
    row = con.execute("SELECT status, body FROM cache2 WHERE url=?", (url,)).fetchone()
    if row:
        return json.loads(row[1]) if row[0] == 200 and row[1] else None
    try:
        request = urllib.request.Request(
            url, headers={"User-Agent": "blast-radius/1.0 (hackathon project)"})
        with urllib.request.urlopen(request, timeout=30) as response:
            body = response.read().decode("utf-8")
        status = 200
    except urllib.error.HTTPError as exc:
        status, body = exc.code, ""
    except Exception:                                  # noqa: BLE001
        return None                                    # transient: do not cache
    time.sleep(PAUSE)
    con.execute("INSERT OR REPLACE INTO cache2 VALUES (?,?,?)", (url, status, body))
    con.commit()
    return json.loads(body) if status == 200 and body else None


def post_json(url, payload):
    data = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(
        url, data=data,
        headers={"Content-Type": "application/json",
                 "User-Agent": "blast-radius/1.0 (hackathon project)"})
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            return json.loads(response.read().decode("utf-8"))
    except Exception as exc:                           # noqa: BLE001
        print(f"    OSV batch failed: {type(exc).__name__}")
        return None


def severity_of(vuln):
    """Best available severity, preferring a CVSS score over a text label."""
    for entry in vuln.get("severity") or []:
        score = entry.get("score")
        if entry.get("type", "").startswith("CVSS") and score:
            try:                       # some feeds give a bare number
                return float(score), entry.get("type")
            except (TypeError, ValueError):
                pass
    for affected in vuln.get("affected") or []:
        rating = ((affected.get("database_specific") or {}).get("severity") or "").upper()
        if rating:
            return {"LOW": 3.1, "MODERATE": 5.5, "MEDIUM": 5.5,
                    "HIGH": 7.5, "CRITICAL": 9.3}.get(rating), rating
    return None, None


def interesting_nodes(G, app_roots):
    """The packages worth spending requests on: whatever the rankings surfaced."""
    wanted = set()
    if os.path.exists(CRITICAL):
        with open(CRITICAL, "r", encoding="utf-8") as f:
            payload = json.load(f)
        for rows in (payload.get("rankings") or {}).values():
            for row in rows:
                wanted.update(row.get("ids") or [row.get("id")])
    if not wanted:
        wanted = {n for n, _ in sorted(G.in_degree, key=lambda x: -x[1])[:200]}
    return sorted(n for n in wanted if n in G and n not in app_roots)


def main():
    try:
        G, app_roots = load_graph()
    except GraphError as exc:
        print(f"ERROR: {exc}")
        sys.exit(1)
    if G is None:
        print("ERROR: graph.json not found. Run: python build.py")
        sys.exit(1)

    nodes = interesting_nodes(G, app_roots)
    print(f"Enriching {len(nodes)} packages\n")

    con = db()

    print("1/2  Known vulnerabilities (OSV.dev)")
    queries = [{"package": {"name": node_name(G, n), "ecosystem": "npm"},
                "version": node_version(G, n)} for n in nodes]
    vuln_ids, by_node = {}, {}
    for start in range(0, len(queries), BATCH):
        chunk = queries[start:start + BATCH]
        print(f"     batch {start // BATCH + 1}/{-(-len(queries) // BATCH)}")
        response = post_json(OSV_BATCH, {"queries": chunk})
        if not response:
            continue
        for node, entry in zip(nodes[start:start + BATCH], response.get("results") or []):
            ids = [v["id"] for v in (entry.get("vulns") or []) if v.get("id")]
            if ids:
                by_node[node] = ids
                for vid in ids:
                    vuln_ids[vid] = None
        time.sleep(PAUSE)

    print(f"     {len(by_node)} packages carry {len(vuln_ids)} distinct advisories")

    details = {}
    for i, vid in enumerate(sorted(vuln_ids)[:MAX_VULN_DETAILS], 1):
        if i % 25 == 0:
            print(f"     detail {i}/{min(len(vuln_ids), MAX_VULN_DETAILS)}")
        vuln = cached_get(con, OSV_VULN + quote(vid, safe=""))
        if not vuln:
            continue
        score, label = severity_of(vuln)
        details[vid] = {
            "id": vid,
            "summary": (vuln.get("summary") or "").strip()[:200],
            "score": score,
            "severity": label,
            "aliases": (vuln.get("aliases") or [])[:3],
        }

    print("\n2/2  Maintainer counts (npm registry)")
    names = sorted({node_name(G, n) for n in nodes})
    maintainers = {}
    for i, name in enumerate(names, 1):
        if i % 25 == 0:
            print(f"     {i}/{len(names)}")

        # The search endpoint is small and fast, but it does not reliably match
        # scoped names like @types/node, so fall back to the package document.
        url = f"{NPM_SEARCH}?text={quote(name, safe='')}&size=1"
        data = cached_get(con, url)
        for obj in (data or {}).get("objects", []):
            package = obj.get("package") or {}
            if package.get("name") == name:
                maintainers[name] = len(package.get("maintainers") or [])
                break

        if name not in maintainers:
            doc = cached_get(con, f"{NPM_REGISTRY}/{quote(name, safe='@')}")
            if doc and doc.get("maintainers") is not None:
                maintainers[name] = len(doc.get("maintainers") or [])
    con.close()

    single = sum(1 for count in maintainers.values() if count == 1)
    print(f"     {len(maintainers)} resolved, {single} with a single maintainer")

    with open(OUT, "w", encoding="utf-8") as f:
        json.dump({
            "generated": time.strftime("%Y-%m-%d %H:%M"),
            "vulns_by_node": by_node,
            "vuln_details": details,
            "maintainers": maintainers,
        }, f)

    print(f"\nWrote {OUT}. Reload the interface to see the advisory and "
          f"maintainer panels.")


if __name__ == "__main__":
    main()
