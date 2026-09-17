"""
Regression tests for the analysis engine.

    python test_engine.py

Each test corresponds to a defect that was found and fixed, so a failure here
means a specific claim the interface makes has stopped being true. No test
framework is required and nothing touches the network; the tests that need a
corpus build a small synthetic one.
"""
from __future__ import annotations

import json
import os
import sys
import traceback

import networkx as nx

import engine as E
from sbom import SbomError, load_sbom

PASSED, FAILED = [], []


def test(fn):
    try:
        fn()
        PASSED.append(fn.__name__)
        print(f"  PASS  {fn.__name__}")
    except AssertionError as exc:
        FAILED.append((fn.__name__, str(exc)))
        print(f"  FAIL  {fn.__name__}: {exc}")
    except Exception:                                   # noqa: BLE001
        FAILED.append((fn.__name__, traceback.format_exc()))
        print(f"  ERROR {fn.__name__}")
        traceback.print_exc()
    return fn


def toy():
    """
    app_pinned ─(pin 1.0.0)──┐
    app_range  ─(^1.0.0)─────┤
                             ├─> middle@1.0.0 ─(^2.0.0)─> victim@2.0.0
    app_direct ─(^2.0.0)─────────────────────────────────┘
    app_two    ─(^1.0.0)─> middle, ─(^3.0.0)─> other@3.0.0 ─(^2.0.0)─> victim
    """
    records = [{
        "root": "npm:app_pinned@1.0.0",
        "nodes": [
            {"id": "npm:app_pinned@1.0.0", "name": "app_pinned", "version": "1.0.0"},
            {"id": "npm:middle@1.0.0", "name": "middle", "version": "1.0.0"},
            {"id": "npm:victim@2.0.0", "name": "victim", "version": "2.0.0"},
        ],
        "edges": [{"from": 0, "to": 1, "requirement": "1.0.0"},
                  {"from": 1, "to": 2, "requirement": "^2.0.0"}],
    }, {
        "root": "npm:app_range@1.0.0",
        "nodes": [
            {"id": "npm:app_range@1.0.0", "name": "app_range", "version": "1.0.0"},
            {"id": "npm:middle@1.0.0", "name": "middle", "version": "1.0.0"},
            {"id": "npm:victim@2.0.0", "name": "victim", "version": "2.0.0"},
        ],
        "edges": [{"from": 0, "to": 1, "requirement": "^1.0.0"},
                  {"from": 1, "to": 2, "requirement": "^2.0.0"}],
    }, {
        "root": "npm:app_direct@1.0.0",
        "nodes": [
            {"id": "npm:app_direct@1.0.0", "name": "app_direct", "version": "1.0.0"},
            {"id": "npm:victim@2.0.0", "name": "victim", "version": "2.0.0"},
        ],
        "edges": [{"from": 0, "to": 1, "requirement": "^2.0.0"}],
    }, {
        "root": "npm:app_two@1.0.0",
        "nodes": [
            {"id": "npm:app_two@1.0.0", "name": "app_two", "version": "1.0.0"},
            {"id": "npm:middle@1.0.0", "name": "middle", "version": "1.0.0"},
            {"id": "npm:other@3.0.0", "name": "other", "version": "3.0.0"},
            {"id": "npm:victim@2.0.0", "name": "victim", "version": "2.0.0"},
        ],
        "edges": [{"from": 0, "to": 1, "requirement": "^1.0.0"},
                  {"from": 0, "to": 2, "requirement": "^3.0.0"},
                  {"from": 1, "to": 3, "requirement": "^2.0.0"},
                  {"from": 2, "to": 3, "requirement": "^2.0.0"}],
    }]
    return E.build_graph(records)


VICTIM = "npm:victim@2.0.0"
FUTURE = {VICTIM: "2.0.1"}


# --- S2-1: a bare major is a range, not a pin ------------------------------

@test
def exact_pin_rejects_partial_ranges():
    for pinned in ("1.2.3", "=1.2.3", " 1.2.3 ", "1.2.3-beta.1", "1.2.3+build.5"):
        assert E.is_exact_pin(pinned), f"{pinned!r} should be a pin"
    for ranged in ("1", "4", "1.2", "^1.2.3", "~1.2.3", ">=1.0.0", "*", "",
                   "1.2.3 || 2.0.0", "1.x", ">= 2.1.2 < 3.0.0"):
        assert not E.is_exact_pin(ranged), f"{ranged!r} is a range, not a pin"


@test
def range_admits_matches_npm_semantics():
    assert E.range_admits("4.2.1", "^4.2.0")
    assert not E.range_admits("4.2.1", "4.2.0")
    assert E.range_admits("1.9.9", "1")          # bare major is 1.x.x
    assert not E.range_admits("2.0.0", "1")
    assert E.range_admits("2.5.0", ">= 2.1.2 < 3.0.0")
    assert not E.range_admits("3.0.0", ">= 2.1.2 < 3.0.0")
    assert E.range_admits("1.0.0", "*") and E.range_admits("1.0.0", None)
    # a requirement we cannot parse must over-report, never silently drop a route
    assert E.range_admits("1.0.0", "git+https://example.invalid/x.git")


@test
def bump_patch_handles_prereleases_and_junk():
    assert E.bump_patch("2.1.3") == "2.1.4"
    assert E.bump_patch("8.0.0-rc.14") == "8.0.1"
    assert E.bump_patch("workspace:*") == "workspace:*"


# --- S1-2: the range check applies at every hop ----------------------------

@test
def gating_applies_beyond_the_first_hop():
    G, roots = toy()
    G.add_edge("npm:deep@1.0.0", "npm:middle@1.0.0", requirement="1.0.0",
               requirements=["1.0.0"])
    G.nodes["npm:deep@1.0.0"].update(name="deep", version="1.0.0")

    future = E.detonate(G, roots, VICTIM, FUTURE)
    # middle is hop 1 and takes it; deep pins middle exactly, so the compromise
    # stops there even though deep is structurally two hops away
    assert "npm:middle@1.0.0" in future["reached"]
    assert "npm:deep@1.0.0" not in future["reached"], \
        "an exact pin two hops out must still block"
    assert any(p["parent"] == "npm:deep@1.0.0" for p in future["pins"])


@test
def lockfile_resident_scenario_gates_nothing():
    G, roots = toy()
    resident = E.detonate(G, roots, VICTIM)
    assert resident["scenario"] == "lockfile-resident"
    assert len(resident["affected_apps"]) == 4, \
        "the version already in the tree reaches every downstream application"
    assert resident["shielded_apps"] == [], \
        "nothing can be shielded from a version that is already installed"


@test
def future_release_scenario_is_gated_by_pins():
    G, roots = toy()
    future = E.detonate(G, roots, VICTIM, FUTURE)
    assert future["scenario"] == "future-release"
    exposed = set(future["affected_apps"])
    assert "npm:app_pinned@1.0.0" not in exposed, "an exact pin must block"
    assert "npm:app_range@1.0.0" in exposed, "a caret range must admit"
    assert "npm:app_direct@1.0.0" in exposed, "a direct caret dependant must be hit"


# --- S1-3: shielding is transitive ----------------------------------------

@test
def shielding_reaches_beyond_direct_dependents():
    G, roots = toy()
    # app_far depends on app_pinned, which is itself shielded
    G.add_edge("npm:app_far@1.0.0", "npm:app_pinned@1.0.0", requirement="^1.0.0",
               requirements=["^1.0.0"])
    G.nodes["npm:app_far@1.0.0"].update(name="app_far", version="1.0.0")
    roots = set(roots) | {"npm:app_far@1.0.0"}

    future = E.detonate(G, roots, VICTIM, FUTURE)
    shielded = set(future["shielded_apps"])
    assert "npm:app_pinned@1.0.0" in shielded
    assert "npm:app_far@1.0.0" in shielded, \
        "shielding must propagate to applications behind a shielded package"
    assert nx.shortest_path_length(G, "npm:app_far@1.0.0", VICTIM) == 3, \
        "and that application is three hops away, not adjacent"


@test
def shielded_and_exposed_are_disjoint():
    G, roots = toy()
    future = E.detonate(G, roots, VICTIM, FUTURE)
    assert not set(future["affected_apps"]) & set(future["shielded_apps"])
    assert set(future["at_risk_apps"]) == (set(future["affected_apps"])
                                           | set(future["shielded_apps"]))


@test
def a_second_open_route_defeats_a_pin():
    G, roots = toy()
    # app_pinned also gets an unpinned route in, so it must become exposed
    G.add_edge("npm:app_pinned@1.0.0", "npm:other@3.0.0", requirement="^3.0.0",
               requirements=["^3.0.0"])
    future = E.detonate(G, roots, VICTIM, FUTURE)
    assert "npm:app_pinned@1.0.0" in future["affected_apps"], \
        "a pin on one route does not shield an application that has another"
    assert "npm:app_pinned@1.0.0" not in future["shielded_apps"]


# --- S1-1: mitigation is verified, not assumed -----------------------------

@test
def mitigation_matches_an_independent_resimulation():
    G, roots = toy()
    future = E.detonate(G, roots, VICTIM, FUTURE)
    plan = E.rank_mitigations(G, roots, future, budget=3)
    replay = E.detonate(G, roots, future["targets"], future["malicious_versions"],
                        immune={fix["id"] for fix in plan["fixes"]})
    assert len(replay["affected_apps"]) == plan["apps_after"], (
        f"claimed {plan['apps_after']} exposed after the upgrades, "
        f"re-simulation says {len(replay['affected_apps'])}")


@test
def mitigation_does_not_claim_an_app_with_two_routes():
    G, roots = toy()
    future = E.detonate(G, roots, VICTIM, FUTURE)
    plan = E.rank_mitigations(G, roots, future, budget=1)
    if plan["fixes"]:
        fix = plan["fixes"][0]
        replay = E.detonate(G, roots, future["targets"], future["malicious_versions"],
                            immune={fix["id"]})
        still = set(fix["apps_covered"]) & set(replay["affected_apps"])
        assert not still, f"claimed protected but still exposed: {sorted(still)}"
        assert fix["apps_saved"] == (len(future["affected_apps"])
                                     - len(replay["affected_apps"]))
    # app_two reaches victim through both middle and other, so upgrading middle
    # alone must not be credited with saving it
    single = E.rank_mitigations(G, roots, future, budget=1)
    for fix in single["fixes"]:
        assert "npm:app_two@1.0.0" not in fix["apps_covered"] or \
            fix["name"] not in ("middle", "other"), \
            "an application with two routes cannot be saved by one upgrade"


@test
def mitigation_never_recommends_a_useless_upgrade():
    G, roots = toy()
    future = E.detonate(G, roots, VICTIM, FUTURE)
    plan = E.rank_mitigations(G, roots, future, budget=5)
    for fix in plan["fixes"]:
        assert fix["apps_saved"] > 0, f"{fix['name']} was recommended but saves nobody"
    assert plan["apps_after"] <= plan["apps_before"]
    assert plan["verified"] is True


@test
def direct_dependants_are_reported_as_unfixable_upstream():
    G, roots = toy()
    future = E.detonate(G, roots, VICTIM, FUTURE)
    plan = E.rank_mitigations(G, roots, future, budget=3)
    assert "npm:app_direct@1.0.0" in plan["direct_apps"], \
        "an application depending on the target directly needs a direct patch"


# --- S2-4: every route is kept, not just the BFS tree ----------------------

@test
def flow_edges_include_redundant_routes():
    G, roots = toy()
    resident = E.detonate(G, roots, VICTIM)
    assert len(resident["flow_edges"]) > len(resident["tree_edges"]), \
        "alternative routes must survive into the drawing"
    into_app_two = [e for e in resident["flow_edges"] if e["from"] == "npm:app_two@1.0.0"]
    assert len(into_app_two) == 2, "app_two has two routes in and both must be drawn"


# --- S2-6 / data integrity -------------------------------------------------

@test
def conflicting_requirements_are_all_retained():
    G, _ = toy()
    reqs = E.edge_requirements(G, "npm:app_pinned@1.0.0", "npm:middle@1.0.0")
    assert reqs == ["1.0.0"]
    # the same edge declared differently by another application keeps both
    records = [
        {"root": "npm:a@1.0.0",
         "nodes": [{"id": "npm:a@1.0.0", "name": "a", "version": "1.0.0"},
                   {"id": "npm:b@1.0.0", "name": "b", "version": "1.0.0"}],
         "edges": [{"from": 0, "to": 1, "requirement": "1.0.0"}]},
        {"root": "npm:c@1.0.0",
         "nodes": [{"id": "npm:c@1.0.0", "name": "c", "version": "1.0.0"},
                   {"id": "npm:a@1.0.0", "name": "a", "version": "1.0.0"},
                   {"id": "npm:b@1.0.0", "name": "b", "version": "1.0.0"}],
         "edges": [{"from": 1, "to": 2, "requirement": "^1.0.0"}]},
    ]
    H, _ = E.build_graph(records)
    assert E.edge_requirements(H, "npm:a@1.0.0", "npm:b@1.0.0") == ["1.0.0", "^1.0.0"]
    assert not E.edge_is_pinned(["1.0.0", "^1.0.0"]), \
        "an edge is only pinned if every declaration is a pin"
    assert E.edge_admits(["1.0.0", "^1.0.0"], "1.0.1"), \
        "an edge carries the compromise if any declaration admits it"


# --- S3-3 / robustness -----------------------------------------------------

@test
def unknown_target_returns_none_rather_than_raising():
    G, roots = toy()
    assert E.detonate(G, roots, "npm:does-not-exist@1.0.0") is None
    assert E.detonate(G, roots, []) is None


@test
def self_loops_and_bad_indices_do_not_break_the_build():
    records = [{
        "root": "npm:x@1.0.0",
        "nodes": [{"id": "npm:x@1.0.0", "name": "x", "version": "1.0.0"},
                  {"id": "npm:y@1.0.0", "name": "y", "version": "1.0.0"}],
        "edges": [{"from": 0, "to": 0, "requirement": "*"},
                  {"from": 0, "to": 1, "requirement": "^1.0.0"},
                  {"from": 9, "to": 1, "requirement": "^1.0.0"}],
    }]
    G, roots = E.build_graph(records)
    assert G.number_of_edges() == 1
    assert not any(u == v for u, v in G.edges())


@test
def pin_fragility_measures_a_real_difference():
    G, roots = toy()
    future = E.detonate(G, roots, VICTIM, FUTURE)
    rows = E.pin_fragility(G, roots, future)
    assert rows, "there is a pin here, so there must be a fragility row"
    for row in rows:
        replay = E.detonate(G, roots, future["targets"], future["malicious_versions"],
                            relaxed={(row["pin"]["parent"], row["pin"]["child"])},
                            detail=False)
        gained = set(replay["affected_apps"]) - set(future["affected_apps"])
        assert len(gained) == row["count"]
    assert rows[0]["count"] >= 1, "widening the pin on app_pinned must expose it"


@test
def name_scope_covers_every_published_version():
    records = [{
        "root": "npm:app@1.0.0",
        "nodes": [{"id": "npm:app@1.0.0", "name": "app", "version": "1.0.0"},
                  {"id": "npm:dup@1.0.0", "name": "dup", "version": "1.0.0"}],
        "edges": [{"from": 0, "to": 1, "requirement": "^1.0.0"}],
    }, {
        "root": "npm:app2@1.0.0",
        "nodes": [{"id": "npm:app2@1.0.0", "name": "app2", "version": "1.0.0"},
                  {"id": "npm:dup@2.0.0", "name": "dup", "version": "2.0.0"}],
        "edges": [{"from": 0, "to": 1, "requirement": "^2.0.0"}],
    }]
    G, roots = E.build_graph(records)
    both = E.nodes_named(G, "dup")
    assert len(both) == 2
    one = E.detonate(G, roots, "npm:dup@1.0.0",
                     {"npm:dup@1.0.0": "1.0.1"}, detail=False)
    allv = E.detonate(G, roots, both,
                      {i: E.bump_patch(E.node_version(G, i)) for i in both},
                      detail=False)
    assert len(one["affected_apps"]) == 1
    assert len(allv["affected_apps"]) == 2, \
        "a maintainer takeover reaches every live release line"


@test
def upgrading_a_package_removes_it_from_the_blast():
    G, roots = toy()
    future = E.detonate(G, roots, VICTIM, FUTURE)
    patched = E.detonate(G, roots, VICTIM, FUTURE, immune={"npm:middle@1.0.0"})
    assert "npm:middle@1.0.0" not in patched["reached"]
    assert len(patched["affected_apps"]) <= len(future["affected_apps"])


# --- persistence and SBOM --------------------------------------------------

@test
def graph_round_trips_through_json():
    G, roots = toy()
    path = "_test_graph.json"
    try:
        E.save_graph(G, roots, path)
        H, back = E.load_graph(path)
        assert set(H.nodes) == set(G.nodes)
        assert set(H.edges) == set(G.edges)
        assert back == set(roots)
        assert E.edge_requirements(H, "npm:app_pinned@1.0.0",
                                   "npm:middle@1.0.0") == ["1.0.0"]
        with open(path, "r", encoding="utf-8") as f:
            json.load(f)          # plain JSON: loading it executes nothing
    finally:
        if os.path.exists(path):
            os.remove(path)


@test
def a_damaged_graph_raises_a_readable_error_not_a_traceback():
    path = "_test_broken.json"
    cases = {
        "truncated JSON": '{"graph": {"nodes": [',
        "missing graph section": '{"app_roots": ["npm:a@1.0.0"]}',
        "no applications": '{"graph": {"nodes": [], "links": []}, "app_roots": []}',
        "graph not a graph": '{"graph": 42, "app_roots": ["npm:a@1.0.0"]}',
    }
    try:
        for label, body in cases.items():
            with open(path, "w", encoding="utf-8") as f:
                f.write(body)
            try:
                E.load_graph(path)
            except E.GraphError as exc:
                assert "build.py" in str(exc), \
                    f"{label}: the error must say how to recover"
            else:
                raise AssertionError(f"{label} should have raised GraphError")
    finally:
        if os.path.exists(path):
            os.remove(path)

    # absent is not the same as damaged: that must stay a quiet (None, None)
    assert E.load_graph("_definitely_missing.json") == (None, None)


@test
def sbom_readers_accept_both_formats_and_reject_junk():
    cyclonedx = json.dumps({
        "bomFormat": "CycloneDX", "specVersion": "1.5",
        "metadata": {"component": {"bom-ref": "root", "name": "my-app",
                                   "version": "1.0.0"}},
        "components": [{"bom-ref": "dep", "name": "left-pad", "version": "1.3.0"}],
        "dependencies": [{"ref": "root", "dependsOn": ["dep"]}],
    })
    record, info = load_sbom(cyclonedx)
    assert record["root"] == "npm:my-app@1.0.0"
    assert info["components"] == 2 and info["dependencies"] == 1

    spdx = json.dumps({
        "spdxVersion": "SPDX-2.3",
        "documentDescribes": ["SPDXRef-app"],
        "packages": [{"SPDXID": "SPDXRef-app", "name": "my-app", "versionInfo": "1.0.0"},
                     {"SPDXID": "SPDXRef-dep", "name": "left-pad", "versionInfo": "1.3.0"}],
        "relationships": [{"spdxElementId": "SPDXRef-app",
                           "relationshipType": "DEPENDS_ON",
                           "relatedSpdxElement": "SPDXRef-dep"}],
    })
    record, info = load_sbom(spdx)
    assert record["root"] == "npm:my-app@1.0.0"
    assert info["dependencies"] == 1

    for junk in ("{not json", "[]", json.dumps({"hello": "world"})):
        try:
            load_sbom(junk)
        except SbomError:
            pass
        else:
            raise AssertionError(f"should have rejected {junk!r}")

    # and an imported SBOM has to survive the rest of the pipeline
    record, _ = load_sbom(cyclonedx)
    G, roots = E.build_graph([record])
    out = E.detonate(G, roots, "npm:left-pad@1.3.0")
    assert out and out["affected_apps"] == ["npm:my-app@1.0.0"]


# --- the shipped corpus, if it has been built ------------------------------

@test
def the_real_corpus_behaves():
    G, roots = E.load_graph()
    if G is None:
        print("        (skipped - run build.py first)")
        return
    assert len(roots) > 50, "the bundled corpus should hold a real portfolio"

    ms = E.nodes_named(G, "ms")
    assert ms, "expected 'ms' in an npm corpus"
    versions = {i: E.bump_patch(E.node_version(G, i)) for i in ms}
    future = E.detonate(G, roots, ms, versions)
    resident = E.detonate(G, roots, ms)

    assert len(resident["affected_apps"]) >= len(future["affected_apps"]), \
        "pins can only ever reduce exposure, never increase it"
    assert future["shielded_apps"], \
        "a real corpus must contain at least one pin that holds something back"

    plan = E.rank_mitigations(G, roots, future, budget=3)
    replay = E.detonate(G, roots, future["targets"], future["malicious_versions"],
                        immune={f["id"] for f in plan["fixes"]})
    assert len(replay["affected_apps"]) == plan["apps_after"]

    for app in future["affected_apps"]:
        chain = future["paths"][app]
        assert chain[0] == app and chain[-1] in set(future["targets"])
        for i in range(len(chain) - 1):
            assert G.has_edge(chain[i], chain[i + 1]), "a path must follow real edges"

    for app in future["shielded_apps"]:
        assert E.pins_for_app(future, app), "a shielded app must name its pins"


def main():
    print("Blast radius - engine regression tests\n")
    if FAILED:
        print(f"\n{len(PASSED)} passed, {len(FAILED)} FAILED\n")
        for name, detail in FAILED:
            print(f"  {name}: {detail.splitlines()[0] if detail else ''}")
        return 1
    print(f"\nAll {len(PASSED)} tests passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
