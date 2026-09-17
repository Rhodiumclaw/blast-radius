"""
Step 1: download real dependency graphs from deps.dev and cache them locally.

Run this first. Everything afterwards reads the cache, so once it finishes the
demo works with the wifi switched off.

    python fetch.py

Failures are cached with their HTTP status, not as a blank. A 404 is final; a
timeout or a rate-limit is retried on the next run. deps.dev does not have a
resolved dependency graph for every version - notably the newest default
version of a fast-moving package - so when the default 404s we walk back
through older releases until one resolves.
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

import nodesemver as ns

API = "https://api.deps.dev/v3"
DB = "cache.db"
SEEDS = "seeds.txt"
OUT = "records.json"
PAUSE = 0.12          # be polite to a free public API
MAX_RETRIES = 3
VERSION_FALLBACKS = 6  # how far back to walk when the default has no graph

FINAL_STATUSES = {400, 401, 403, 404, 410}


def db():
    con = sqlite3.connect(DB)
    con.execute("CREATE TABLE IF NOT EXISTS cache2 ("
                "url TEXT PRIMARY KEY, status INTEGER, body TEXT)")
    # Carry over successful responses from the older two-column cache so a
    # re-run costs nothing. Failures are deliberately not carried over: the old
    # schema could not tell a 404 from a dropped connection.
    have_old = con.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='cache'"
    ).fetchone()
    if have_old:
        con.execute("INSERT OR IGNORE INTO cache2 (url, status, body) "
                    "SELECT url, 200, body FROM cache WHERE body <> ''")
        con.commit()
    return con


def get(con, url):
    """Fetch a URL once. Successes and final failures are cached; transient
    failures are not, so re-running picks them up."""
    row = con.execute("SELECT status, body FROM cache2 WHERE url=?", (url,)).fetchone()
    if row:
        status, body = row
        return json.loads(body) if status == 200 and body else None

    status, body = 0, ""
    for attempt in range(MAX_RETRIES):
        try:
            req = urllib.request.Request(
                url, headers={"User-Agent": "blast-radius/1.0 (hackathon project)"})
            with urllib.request.urlopen(req, timeout=30) as response:
                body = response.read().decode("utf-8")
                status = 200
            break
        except urllib.error.HTTPError as exc:
            status = exc.code
            if status in FINAL_STATUSES:
                break
            time.sleep(PAUSE * (2 ** attempt) * 8)   # back off on 429 / 5xx
        except Exception as exc:                      # noqa: BLE001 - network is messy
            status = 0
            print(f"    retry {attempt + 1}/{MAX_RETRIES} after {type(exc).__name__}")
            time.sleep(PAUSE * (2 ** attempt) * 8)

    time.sleep(PAUSE)

    if status == 200 or status in FINAL_STATUSES:
        con.execute("INSERT OR REPLACE INTO cache2 VALUES (?,?,?)", (url, status, body))
        con.commit()
    if status != 200:
        print(f"    HTTP {status or 'error'} for {url.split('/packages/')[-1][:60]}")
        return None
    return json.loads(body) if body else None


def _sort_key(version):
    try:
        parsed = ns.make_semver(version, loose=True)
        return (0 if not parsed.prerelease else 1,
                -parsed.major, -parsed.minor, -parsed.patch)
    except Exception:
        return (2, 0, 0, 0)


def candidate_versions(con, name):
    """Versions to try, best first: the registry default, then newest downward."""
    data = get(con, f"{API}/systems/npm/packages/{quote(name, safe='')}")
    if not data:
        return []
    versions = [v["versionKey"]["version"] for v in data.get("versions", [])
                if v.get("versionKey", {}).get("version")]
    if not versions:
        return []
    default = next((v["versionKey"]["version"] for v in data.get("versions", [])
                    if v.get("isDefault")), None)
    ordered = sorted(set(versions), key=_sort_key)
    if default:
        ordered = [default] + [v for v in ordered if v != default]
    return ordered[:VERSION_FALLBACKS]


def dependency_graph(con, name, version):
    url = (f"{API}/systems/npm/packages/{quote(name, safe='')}"
           f"/versions/{quote(version, safe='')}:dependencies")
    return get(con, url)


def resolve(con, name):
    """The newest version of a package that deps.dev can actually resolve."""
    for version in candidate_versions(con, name):
        data = dependency_graph(con, name, version)
        if data and data.get("nodes"):
            return version, data
        print(f"    no resolved graph for {name}@{version}, trying an older release")
    return None, None


def main():
    if not os.path.exists(SEEDS):
        print(f"ERROR: {SEEDS} not found. Create it with one package name per line.")
        sys.exit(1)

    with open(SEEDS, "r", encoding="utf-8") as f:
        names = [l.strip() for l in f if l.strip() and not l.startswith("#")]
    print(f"Corpus: {len(names)} packages\n")

    con = db()
    records, failed = [], []

    for i, name in enumerate(names, 1):
        print(f"[{i}/{len(names)}] {name}")
        version, data = resolve(con, name)
        if not data:
            failed.append(name)
            continue

        nodes = []
        for n in data["nodes"]:
            vk = n.get("versionKey") or {}
            if not vk.get("name") or not vk.get("version"):
                nodes.append(None)
                continue
            nodes.append({
                "id": f"npm:{vk['name']}@{vk['version']}",
                "name": vk["name"],
                "version": vk["version"],
            })
        if not nodes or nodes[0] is None:
            failed.append(name)
            continue

        edges = []
        for e in data.get("edges", []):
            src, dst = e.get("fromNode"), e.get("toNode")
            if src is None or dst is None:
                continue
            if not (0 <= src < len(nodes)) or not (0 <= dst < len(nodes)):
                continue
            if nodes[src] is None or nodes[dst] is None:
                continue
            edges.append({"from": src, "to": dst,
                          "requirement": e.get("requirement") or "*"})

        records.append({
            "root": nodes[0]["id"],
            "nodes": [n if n else {"id": "npm:?@0.0.0", "name": "?", "version": "0.0.0"}
                      for n in nodes],
            "edges": edges,
        })
        print(f"    {version}: {len(nodes)} packages, {len(edges)} edges")

    con.close()

    with open(OUT, "w", encoding="utf-8") as f:
        json.dump(records, f)

    print(f"\nDone. {len(records)} of {len(names)} applications saved to {OUT}")
    if failed:
        print(f"Could not resolve {len(failed)}: {', '.join(failed)}")
    print(f"Total package-versions fetched: {sum(len(r['nodes']) for r in records)}")
    print("\nNext: python build.py")


if __name__ == "__main__":
    main()
