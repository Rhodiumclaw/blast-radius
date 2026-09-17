"""
Turn a simulation into a one-page incident brief someone can act on.

The person who has to make the upgrade is usually not the person who ran the
scan, so the output is plain Markdown: paste it into a ticket, a channel, or an
email without reformatting.
"""
from __future__ import annotations

import time

from engine import node_name, node_version, pins_for_app


def _label(G, node):
    return f"{node_name(G, node)}@{node_version(G, node)}"


def incident_brief(G, app_roots, result, mitigation, fragility=None, corpus="portfolio"):
    targets = result["targets"]
    head = ", ".join(_label(G, t) for t in targets)
    versions = ", ".join(sorted(set(result["malicious_versions"].values())))
    exposed = result["affected_apps"]
    shielded = result["shielded_apps"]

    lines = [
        f"# Supply-chain exposure: {node_name(G, targets[0])}",
        "",
        f"*Generated {time.strftime('%Y-%m-%d %H:%M')} · corpus: {corpus} "
        f"({len(app_roots)} applications)*",
        "",
        "## What was simulated",
        "",
        f"- **Compromised package:** {head}",
        f"- **Malicious version:** {versions}",
        f"- **Scenario:** {result['scenario']} — "
        + ("the attacker publishes a new release, so every hop is gated by the "
           "declared version ranges."
           if result["republish"] else
           "the malicious code is the version already resolved in the tree, so "
           "no republish is needed and every downstream consumer already has it."),
        "",
        "## Impact",
        "",
        f"- **{len(exposed)} of {len(app_roots)} applications exposed** "
        f"({result['exposure_pct']}% of the portfolio), within {result['max_hops']} hop(s).",
        f"- **{len(result['reached'])} package-versions** carry the compromise.",
        f"- **{len(shielded)} further applications are shielded** by version pins — "
        "lagged, not safe.",
        "",
    ]

    if exposed:
        lines += ["### Applications exposed", ""]
        for app in exposed:
            hops = result["depth"].get(app, "?")
            chain = " ← ".join(node_name(G, x) for x in result["paths"].get(app, [app]))
            lines.append(f"- **{node_name(G, app)}** — {hops} hop(s): `{chain}`")
        lines.append("")

    lines += ["## Recommended action", ""]
    if mitigation["fixes"]:
        lines.append(
            f"Each upgrade below was verified by re-running the propagation with that "
            f"package patched. Together they take exposure from **{mitigation['apps_before']} "
            f"to {mitigation['apps_after']} applications** "
            f"({mitigation['reduction_pct']}% reduction).")
        lines.append("")
        for i, fix in enumerate(mitigation["fixes"], 1):
            covered = ", ".join(node_name(G, a) for a in fix["apps_covered"])
            lines.append(f"{i}. **Upgrade `{_label(G, fix['id'])}`** — "
                         f"removes exposure for {fix['apps_saved']} application(s)"
                         + (f": {covered}" if covered else ""))
        lines.append("")
    else:
        lines += ["No upstream upgrade reduces exposure — every exposed application "
                  "depends on the compromised package directly.", ""]

    if mitigation["direct_apps"]:
        names = ", ".join(node_name(G, a) for a in mitigation["direct_apps"])
        lines += [f"**Needs a direct patch** (no upstream package sits in the way): "
                  f"{names}", ""]

    if shielded:
        lines += ["## Watch list — shielded by a pin today", ""]
        for app in shielded:
            pins = pins_for_app(result, app)
            detail = "; ".join(
                f"`{p['parent_name']}` requires `{p['child_name']}` at "
                f"`{p['requirement']}`, which will not take `{p['needed_version']}`"
                for p in pins[:3])
            more = f" (+{len(pins) - 3} more)" if len(pins) > 3 else ""
            lines.append(f"- **{node_name(G, app)}** — {len(pins)} pin(s) holding: "
                         f"{detail}{more}")
        lines.append("")

    if fragility:
        lines += ["## Most fragile pins", "",
                  "If one of these ranges is widened, the applications listed become "
                  "exposed immediately.", ""]
        for row in fragility[:5]:
            pin = row["pin"]
            if not row["count"]:
                continue
            names = ", ".join(node_name(G, a) for a in row["newly_exposed"])
            lines.append(f"- `{_label(G, pin['parent'])}` → `{_label(G, pin['child'])}` "
                         f"pinned to `{pin['requirement']}` — widening exposes "
                         f"{row['count']}: {names}")
        lines.append("")

    lines += [
        "## Method",
        "",
        "Every figure above is a count produced by simulating propagation over a "
        "dependency graph resolved from public registry data. Exposure is measured "
        "by walking the graph upward from the compromised package and testing each "
        "declared version range against the version that edge would have to accept. "
        "Mitigation figures are differences between two simulation runs, not "
        "estimates.",
        "",
        "Reachability is not the same as exploitability: this models whether "
        "malicious code reaches a build, not whether a vulnerable function is called.",
    ]
    return "\n".join(lines)
