"""
Core analysis engine: dependency graph, semver-gated propagation, mitigation.

No network access here - this module only works on cached data, so the
interface runs with the wifi switched off.

The model in one paragraph
--------------------------
A compromise starts at one or more package-versions. It spreads *upward*, into
things that depend on them. Whether it crosses a dependency edge is decided by
the declared version range on that edge and by the version the parent would
actually have to accept:

  * Lockfile-resident scenario - the malicious code is the version already
    resolved in the tree. Nothing has to be republished, so every edge that was
    already resolved admits it and the compromise reaches everything downstream.

  * Future-release scenario - the attacker publishes a *new* version. The
    package's direct dependents only take it if their declared range admits it,
    and a dependent that does take it must itself publish a new release before
    *its* dependents are affected. So the range check applies at every hop, not
    just the first one.

Which scenario is in play is derived from the simulated version, never guessed.
"""
from __future__ import annotations

import json
import os
import re
from collections import Counter, deque

import networkx as nx
import nodesemver as ns

GRAPH_FILE = "graph.json"

SCOPE_VERSION = "version"
SCOPE_NAME = "name"

# A version with all three numeric parts, optionally "="-prefixed and optionally
# carrying a prerelease/build suffix. Anything looser ("1", "1.2", "^1.2.3") is a
# range, not a pin.
_EXACT_PIN = re.compile(r"^=?\s*v?\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.\-]+)*$")
_SEMVER_HEAD = re.compile(r"^\s*v?(\d+)\.(\d+)\.(\d+)")


# ---------------------------------------------------------------------------
# semver primitives
# ---------------------------------------------------------------------------

def range_admits(version, requirement):
    """Does a declared dependency range accept this version?

    This is the gate the whole model turns on.

        "^4.2.0"  accepts 4.2.1  -> the compromise flows through
        "4.2.0"   exact pin      -> the compromise is blocked for now
    """
    if requirement is None:
        return True
    requirement = str(requirement).strip()
    if requirement in ("", "*", "x", "X", "latest"):
        return True

    # A git URL, "workspace:*", "file:../x" or a dist-tag is not a range at all.
    # node-semver answers False for these rather than raising, which would make
    # them look like pins that block the compromise - so they are screened out
    # first and assumed to admit. Over-reporting exposure is the safe direction.
    try:
        if ns.valid_range(requirement, loose=True) is None:
            return True
    except Exception:                                   # noqa: BLE001
        return True

    try:
        return bool(ns.satisfies(version, requirement, loose=True))
    except Exception:                                   # noqa: BLE001
        return True


def is_exact_pin(requirement):
    """True only for a requirement that names one complete version.

    A bare major like "1" means 1.x.x - the widest common range - and must not
    be mistaken for a pin.
    """
    if requirement is None:
        return False
    return bool(_EXACT_PIN.match(str(requirement).strip()))


def bump_patch(version):
    """The next patch release of a version, or the input if it isn't semver."""
    m = _SEMVER_HEAD.match(str(version))
    if not m:
        return str(version)
    major, minor, patch = m.groups()
    return f"{major}.{minor}.{int(patch) + 1}"


# ---------------------------------------------------------------------------
# edge helpers
# ---------------------------------------------------------------------------

def edge_requirements(G, parent, child):
    """Every distinct range declared on this edge across the whole corpus."""
    data = G.edges[parent, child]
    reqs = data.get("requirements")
    if reqs:
        return list(reqs)
    return [data.get("requirement", "*")]


def edge_admits(requirements, version):
    """The edge carries the compromise if *any* declared range admits it."""
    return any(range_admits(version, r) for r in requirements)


def edge_is_pinned(requirements):
    """The edge blocks future releases only if *every* declared range is a pin."""
    return bool(requirements) and all(is_exact_pin(r) for r in requirements)


# ---------------------------------------------------------------------------
# graph construction
# ---------------------------------------------------------------------------

def build_graph(records):
    """
    records: list of {"root": "npm:name@ver", "nodes": [...], "edges": [...]}

    Returns a DiGraph where an edge parent -> child means "parent depends on
    child". Every distinct requirement string declared for an edge anywhere in
    the corpus is kept, so a range declared by one application is never silently
    overwritten by another application's.
    """
    G = nx.DiGraph()
    app_roots = set()
    declared = {}

    for rec in records:
        idx = rec["nodes"]
        app_roots.add(rec["root"])
        for n in idx:
            G.add_node(n["id"], name=n["name"], version=n["version"])
        for e in rec["edges"]:
            try:
                src, dst = idx[e["from"]]["id"], idx[e["to"]]["id"]
            except (IndexError, KeyError, TypeError):
                continue
            if src == dst:
                continue
            req = e.get("requirement") or "*"
            declared.setdefault((src, dst), set()).add(str(req).strip() or "*")

    for (src, dst), reqs in declared.items():
        ordered = sorted(reqs)
        G.add_edge(src, dst, requirement=ordered[0], requirements=ordered)

    return G, app_roots


def nodes_named(G, name):
    """Every package-version in the graph carrying this package name."""
    return sorted(n for n, d in G.nodes(data=True) if d.get("name") == name)


def node_name(G, node):
    return G.nodes[node].get("name", node) if node in G else node


def node_version(G, node):
    return G.nodes[node].get("version", "?") if node in G else "?"


# ---------------------------------------------------------------------------
# propagation
# ---------------------------------------------------------------------------

def detonate(G, app_roots, targets, malicious_versions=None, immune=None,
             relaxed=None, detail=True):
    """
    Simulate a compromise and propagate it upward through everything that
    depends on the target, gating every hop on the declared semver ranges.

    targets            one node id, or several (all published versions of a
                       package name, for a maintainer-account takeover).
    malicious_versions {node id: version}; defaults to the installed version,
                       which selects the lockfile-resident scenario.
    immune             nodes that have already been patched - they neither take
                       the compromise nor pass it on. This is how a candidate
                       upgrade is simulated.
    relaxed            edges (parent, child) whose range is treated as widened,
                       for asking "what if this pin moves?".
    detail             False skips path/shield reconstruction, for bulk ranking.
    """
    immune = set(immune or ())
    relaxed = set(relaxed or ())
    if isinstance(targets, str):
        targets = [targets]

    target_set = {t for t in targets if t in G and t not in immune}
    if not target_set:
        return None

    supplied = malicious_versions or {}
    versions, republish = {}, False
    for t in target_set:
        installed = G.nodes[t].get("version") or "0.0.0"
        versions[t] = str(supplied.get(t) or installed).strip() or installed
        if versions[t] != installed:
            republish = True

    def carrier(node):
        """The version a node would be shipping once the compromise reaches it."""
        if node in target_set:
            return versions[node]
        installed = G.nodes[node].get("version") or "0.0.0"
        # In the future-release scenario an intermediate has to cut a new release
        # to pass the compromise on, and that release is what its own dependents'
        # ranges get tested against.
        return bump_patch(installed) if republish else installed

    depth = {t: 0 for t in target_set}
    parent_of = {t: None for t in target_set}
    queue = deque(sorted(target_set))
    blocked = []

    while queue:
        node = queue.popleft()
        carried = carrier(node)
        for parent in G.predecessors(node):
            if parent in immune:
                continue
            reqs = edge_requirements(G, parent, node)
            if (parent, node) not in relaxed and not edge_admits(reqs, carried):
                blocked.append((parent, node, tuple(reqs), carried))
                continue
            if parent in depth:
                continue
            depth[parent] = depth[node] + 1
            parent_of[parent] = node
            queue.append(parent)

    infected = set(depth)
    exposed = infected - target_set
    affected_apps = sorted(exposed & app_roots)
    total_apps = max(len(app_roots), 1)

    result = {
        "targets": sorted(target_set),
        "malicious_versions": versions,
        "republish": republish,
        "scenario": "future-release" if republish else "lockfile-resident",
        "reached": exposed,
        "depth": depth,
        "infected_from": parent_of,
        "affected_apps": affected_apps,
        "exposure_pct": round(100 * len(affected_apps) / total_apps, 1),
        "max_hops": max(depth.values()) if depth else 0,
        "blocked_edges": len(blocked),
        "immune": sorted(immune),
    }

    if not detail:
        result.update({"pins": [], "shielded_apps": [], "guarded_by": {},
                       "shield_depth": {}, "shield_edges": [], "paths": {},
                       "flow_edges": [], "tree_edges": [],
                       "at_risk_apps": list(affected_apps)})
        return result

    # --- shielding, propagated transitively -------------------------------
    # A pin on the frontier does not only protect the package that declares it;
    # it protects everything that can only be reached through that package.
    pins, guarded_by, shield_edges, shield_depth = [], {}, set(), {}
    for parent, child, reqs, carried in blocked:
        if parent in infected:
            continue  # a pin here, but the compromise arrived by another route
        pin_id = len(pins)
        pins.append({
            "id": pin_id,
            "parent": parent,
            "parent_name": node_name(G, parent),
            "child": child,
            "child_name": node_name(G, child),
            "requirements": list(reqs),
            "requirement": reqs[0] if reqs else "*",
            "needed_version": carried,
            "exact_pin": edge_is_pinned(reqs),
        })
        shield_edges.add((parent, child))
        # Breadth-first so each shielded node also learns how far it sits beyond
        # the blocked frontier. That distance is what lets the interface lay the
        # graph out in layers instead of as a hairball.
        frontier = deque([(parent, depth[child] + 1)])
        seen = {parent}
        while frontier:
            here, distance = frontier.popleft()
            guarded_by.setdefault(here, []).append(pin_id)
            if distance < shield_depth.get(here, 10 ** 9):
                shield_depth[here] = distance
            for above in G.predecessors(here):
                if above in infected or above in immune:
                    continue
                # a real dependency edge, walked upward through the region the
                # pin protects - so the blocked route can be drawn, not implied
                shield_edges.add((above, here))
                if above in seen:
                    continue
                seen.add(above)
                frontier.append((above, distance + 1))

    shielded_apps = sorted(set(guarded_by) & app_roots)

    # --- one concrete route per affected application ----------------------
    paths = {}
    for app in affected_apps:
        chain, cur = [], app
        while cur is not None:
            chain.append(cur)
            cur = parent_of.get(cur)
        paths[app] = chain

    # --- every route, not just the BFS tree -------------------------------
    # Half the applications in a real corpus have more than one way in. Drawing
    # only the tree hides exactly the redundancy that makes a single upgrade
    # insufficient.
    flow_edges = []
    for child in infected:
        carried = carrier(child)
        for parent in G.predecessors(child):
            if parent not in infected:
                continue
            reqs = edge_requirements(G, parent, child)
            if (parent, child) in relaxed or edge_admits(reqs, carried):
                flow_edges.append({
                    "from": parent,
                    "to": child,
                    "hop": max(depth[parent], depth[child]),
                    "tree": parent_of.get(parent) == child,
                })

    result.update({
        "pins": pins,
        "shielded_apps": shielded_apps,
        "guarded_by": guarded_by,
        "shield_depth": shield_depth,
        "shield_edges": sorted(shield_edges),
        "paths": paths,
        "flow_edges": flow_edges,
        "tree_edges": [e for e in flow_edges if e["tree"]],
        "at_risk_apps": sorted(set(affected_apps) | set(shielded_apps)),
    })
    return result


def shielded_route(result, app, max_nodes=40):
    """
    The real dependency edges linking a shielded application down to the pins
    that are holding the compromise back, so a blocked route can be drawn
    rather than asserted.
    """
    adjacency = {}
    for parent, child in result.get("shield_edges", ()):
        adjacency.setdefault(parent, []).append(child)

    pin_children = {p["child"] for p in result.get("pins", [])}
    edges, seen, stack = [], {app}, [app]
    while stack and len(seen) < max_nodes:
        here = stack.pop()
        for below in adjacency.get(here, ()):
            edges.append((here, below))
            if below in pin_children or below in seen:
                continue
            seen.add(below)
            stack.append(below)
    return edges


def pins_for_app(result, app):
    """The pins currently standing between a shielded application and the blast."""
    ids = result.get("guarded_by", {}).get(app, [])
    by_id = {p["id"]: p for p in result.get("pins", [])}
    return [by_id[i] for i in ids if i in by_id]


# ---------------------------------------------------------------------------
# criticality ranking
# ---------------------------------------------------------------------------

def rank_critical(G, app_roots, scope=SCOPE_VERSION, limit=40, pool=400):
    """
    Which packages, if compromised, reach the most applications?

    Ranked on the future-release scenario - an attacker publishing a malicious
    new version - because that is the threat pins actually defend against. The
    lockfile-resident number is reported alongside so the gap between "already
    in your tree" and "would be taken tomorrow" is visible rather than implied.
    """
    if scope == SCOPE_NAME:
        by_name = {}
        for node, data in G.nodes(data=True):
            by_name.setdefault(data.get("name", node), []).append(node)
        app_names = {node_name(G, a) for a in app_roots}
        candidates = sorted(
            by_name.items(),
            key=lambda kv: -sum(G.in_degree(n) for n in kv[1]),
        )[:pool]
        groups = [(name, ids) for name, ids in candidates if name not in app_names]
    else:
        ordered = sorted(G.nodes, key=lambda n: -G.in_degree(n))[:pool]
        groups = [(node_name(G, n), [n]) for n in ordered if n not in app_roots]

    total_apps = max(len(app_roots), 1)
    scored = []
    for name, ids in groups:
        future = detonate(G, app_roots, ids,
                          malicious_versions={i: bump_patch(node_version(G, i)) for i in ids},
                          detail=False)
        if not future:
            continue
        resident = detonate(G, app_roots, ids, detail=False)
        now = len(resident["affected_apps"]) if resident else 0
        if not future["affected_apps"] and not now:
            continue
        scored.append({
            "key": name if scope == SCOPE_NAME else ids[0],
            "ids": ids,
            "id": ids[0],
            "name": name,
            "version": node_version(G, ids[0]) if scope == SCOPE_VERSION else f"{len(ids)} version(s)",
            "apps": len(future["affected_apps"]),
            "exposure_pct": future["exposure_pct"],
            "apps_now": now,
            "now_pct": round(100 * now / total_apps, 1),
            "held_back": max(now - len(future["affected_apps"]), 0),
            "direct_dependents": sum(G.in_degree(i) for i in ids),
        })

    scored.sort(key=lambda x: (-x["apps"], -x["apps_now"], x["name"]))
    return scored[:limit]


# ---------------------------------------------------------------------------
# mitigation, verified by re-simulation
# ---------------------------------------------------------------------------

def rank_mitigations(G, app_roots, result, budget=3, pool=12):
    """
    Rank upgrades by the drop they actually cause.

    The greedy hitting set over propagation paths is only used to *propose*
    candidates. Every proposal is then verified by re-running the propagation
    with that package patched, and the number reported is the measured drop in
    exposed applications - not an assumption that cutting one route saves an
    application that had two.
    """
    targets = set(result["targets"])
    versions = result["malicious_versions"]

    direct_apps = sorted({
        parent for t in targets for parent in G.predecessors(t)
        if parent in app_roots
    } & set(result["affected_apps"]))

    before = len(result["affected_apps"])
    current = result
    immune, chosen = set(), []

    for _ in range(max(int(budget), 0)):
        exposed_now = set(current["affected_apps"])
        if not exposed_now:
            break

        # propose: packages sitting on the most remaining routes
        counts = Counter()
        for app, chain in current["paths"].items():
            for node in chain[1:-1]:  # exclude the application and the target
                if node in targets or node in app_roots or node in immune:
                    continue
                counts[node] += 1
        if not counts:
            break

        best = None
        for candidate, _freq in counts.most_common(max(int(pool), 1)):
            trial = detonate(G, app_roots, sorted(targets), versions,
                             immune=immune | {candidate})
            if trial is None:
                continue
            remaining = len(trial["affected_apps"])
            if best is None or remaining < best[1]:
                best = (candidate, remaining, trial)

        if best is None or best[1] >= len(exposed_now):
            break  # nothing left that measurably helps

        candidate, remaining, trial = best
        immune.add(candidate)
        chosen.append({
            "id": candidate,
            "name": node_name(G, candidate),
            "version": node_version(G, candidate),
            "apps_saved": len(exposed_now) - remaining,
            "apps_covered": sorted(exposed_now - set(trial["affected_apps"])),
            "apps_remaining": remaining,
        })
        current = trial

    after = len(current["affected_apps"])
    return {
        "fixes": chosen,
        "apps_before": before,
        "apps_after": after,
        "direct_apps": direct_apps,
        "reduction_pct": round(100 * (before - after) / before, 1) if before else 0.0,
        "verified": True,
        "final": current,
    }


# ---------------------------------------------------------------------------
# "pinned is lagged, not safe" - measured rather than asserted
# ---------------------------------------------------------------------------

def pin_fragility(G, app_roots, result, limit=10):
    """
    For every pin currently holding the compromise back, measure what happens
    the moment it moves: re-run the propagation with that one range widened and
    count the applications that become exposed.

    This turns "latent exposure" from a claim into a number, without inventing
    a probability for how likely the maintainer is to bump.
    """
    targets = result["targets"]
    versions = result["malicious_versions"]
    baseline = set(result["affected_apps"])

    rows = []
    for pin in result.get("pins", []):
        trial = detonate(G, app_roots, targets, versions,
                         relaxed={(pin["parent"], pin["child"])}, detail=False)
        if trial is None:
            continue
        newly = sorted(set(trial["affected_apps"]) - baseline)
        rows.append({
            "pin": pin,
            "newly_exposed": newly,
            "count": len(newly),
        })

    rows.sort(key=lambda r: -r["count"])
    return rows[:limit]


# ---------------------------------------------------------------------------
# hop-by-hop reasoning
# ---------------------------------------------------------------------------

def explain_path(G, chain, result):
    """
    Turn one propagation chain (app -> ... -> target) into the actual semver
    reasoning at each hop: which range was checked, which version it had to
    admit, and why that version is the one being checked.
    """
    targets = set(result["targets"])
    versions = result["malicious_versions"]
    republish = result["republish"]

    def carrier(node):
        if node in targets:
            return versions.get(node, node_version(G, node))
        installed = node_version(G, node)
        return bump_patch(installed) if republish else installed

    steps = []
    n = len(chain)
    for k in range(n - 2, -1, -1):
        parent, child = chain[k], chain[k + 1]
        reqs = edge_requirements(G, parent, child)
        steps.append({
            "hop": n - 1 - k,
            "parent": parent,
            "parent_name": node_name(G, parent),
            "child": child,
            "child_name": node_name(G, child),
            "requirements": reqs,
            "requirement": " | ".join(reqs),
            "version": carrier(child),
            "origin": child in targets,
            "exact_pin": edge_is_pinned(reqs),
        })
    return steps


# ---------------------------------------------------------------------------
# persistence - plain JSON, so nothing here executes code on load
# ---------------------------------------------------------------------------

def save_graph(G, app_roots, path=GRAPH_FILE):
    payload = {
        "graph": nx.node_link_data(G, edges="edges"),
        "app_roots": sorted(app_roots),
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f)


class GraphError(Exception):
    """graph.json exists but cannot be used. Distinct from it being absent, so a
    caller can tell 'not built yet' apart from 'built and damaged'."""


def load_graph(path=GRAPH_FILE):
    if not os.path.exists(path):
        return None, None
    try:
        with open(path, "r", encoding="utf-8") as f:
            payload = json.load(f)
    except (json.JSONDecodeError, UnicodeDecodeError, OSError) as exc:
        raise GraphError(f"{path} is not readable JSON ({exc}). It is probably "
                         f"truncated - rebuild it with: python build.py") from exc

    if not isinstance(payload, dict) or "graph" not in payload:
        raise GraphError(f"{path} is missing its 'graph' section. "
                         f"Rebuild it with: python build.py")
    try:
        G = nx.node_link_graph(payload["graph"], directed=True, multigraph=False,
                               edges="edges")
    except Exception as exc:                            # noqa: BLE001
        raise GraphError(f"{path} does not contain a usable dependency graph "
                         f"({type(exc).__name__}). Rebuild it with: "
                         f"python build.py") from exc

    roots = payload.get("app_roots")
    if not isinstance(roots, list) or not roots:
        raise GraphError(f"{path} lists no applications. "
                         f"Rebuild it with: python build.py")
    return G, set(roots)
