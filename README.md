# Blast radius

Most dependency scanners look at one repository at a time and rank findings by CVSS
severity. That answers "which packages are vulnerable" but not the question an
engineering organisation actually has: **across everything we run, which single package
compromise hurts us most, and which one upgrade buys back the most safety?**

This tool answers that by building one dependency graph across a whole portfolio of
applications, inverting it, and simulating a compromise.

Here is the argument in one number. Against the 40 most structurally critical packages
in the bundled corpus, OSV.dev reports **zero** known advisories — a vulnerability
scanner would show a clean board. The graph shows that compromising just one of them
reaches **17 of 121 applications**.

## Three ideas that make it different

**1. Semver-gated propagation, at every hop.** A compromise does not spread to
everything that is technically reachable. It only travels a dependency edge if the
parent's *declared version range* would resolve to the malicious version.

    "^4.2.0"  accepts 4.2.1  ->  the compromise flows through
    "4.2.0"   exact pin      ->  the compromise is blocked, for now

The gate applies at every level, not just the first. A package that takes a malicious
dependency has to publish its own release before *its* dependents are affected, and
that release is what the next range up has to accept. So there are two scenarios, and
the tool keeps them apart:

| Scenario | What it models | What pins do |
|---|---|---|
| **Already in your tree** | The malicious code *is* the version your lockfile resolved. | Nothing. It is already installed everywhere downstream. |
| **Next release** | The attacker publishes a *new* version. | Gate every hop. |

Shielded does not mean safe. It means lagged: exposed the moment a maintainer widens
a range or bumps a pin. Shielding is transitive — an application counts as shielded
when *every* route in is blocked, including when the pin doing the blocking sits
several hops away.

**2. Mitigation by counterfactual, not by counting.** For each candidate upgrade the
tool applies the patch to the graph and **re-runs the propagation**. The number on
screen is the measured drop in exposed applications. This matters: many applications
have more than one route to a given package, so an
upgrade that severs one route often saves nobody. A greedy hitting set is used only to
*propose* candidates; every proposal is then verified by simulation.

**3. Latent exposure, measured.** "Pinned is lagged, not safe" is easy to assert. The
*Fragile pins* tab widens exactly one range, re-runs the propagation, and reports how
many applications become exposed — no invented probability for how likely a maintainer
is to bump.

Every number on screen is a count produced by the simulation. Nothing is a weighted
score with invented coefficients.

## Setup

    pip install -r requirements.txt

## Run

    python fetch.py       # downloads real dependency data, caches to SQLite (slow, once)
    python build.py       # builds the graph, precomputes criticality
    python enrich.py      # optional: adds OSV advisories and maintainer counts
    python -m streamlit run app.py  # opens the interface in your browser

`fetch.py` and `enrich.py` are the only steps that need the internet. Everything
afterwards reads the local cache, and the graph renderer is **inlined into the page**
rather than pulled from a CDN, so the interface runs with the network cable out.

Verify the analysis at any time:

    python test_engine.py     # 24 regression tests, no network, no framework needed

## The interface

**Blast rings.** The compromised package sits at ground zero and every hop is a ring
further out, so distance from the centre is distance from the compromise. Positions are
computed deterministically in Python rather than settled by a physics engine, so the
picture is identical every time it is drawn. The camera opens tight on the centre and
eases outward as each ring lands. An *Organic* force-directed view is one click away.

**Click any node to trace it.** Selecting a package lights the exact chain carrying the
compromise back to ground zero in white and drops everything else to 13% opacity — one
clean thread through a hundred nodes.

**Show: routes that reach you.** The blast reaches plenty of packages that lead nowhere
you own. They stay in every metric, but the drawing defaults to the packages that
actually carry the compromise to one of your applications. The caption under the graph
says exactly how many are hidden.

**Real incidents, as presets.** `colors`, `faker`, `rc`, `eslint-scope`, `is-promise`
and `minimist` were all genuinely attacked or sabotaged in the wild, and this portfolio
still depends on them. Simulated in the *already in your tree* scenario, this is what
they are worth against this corpus:

| Package | Applications reached |
|---|---|
| `minimist` | 3 |
| `colors` | 2 |
| `rc` | 1 |
| `eslint-scope` | 1 |
| `is-promise` | 1 |
| `faker` | 0 |
| **`ms`** — never attacked, six lines long | **26** |

Under *next release*, where version pins gate every hop, `ms` still reaches 17 and
holds 9 more behind pins. Fame and CVE severity do not predict blast radius; position
in the graph does.

## Beyond the interface

**Point it at your own software.** The bundled corpus is 121 popular npm packages
treated as a portfolio. Upload a CycloneDX or SPDX SBOM in the sidebar to analyse your
own instead — there is a ready-made example in `examples/`. A BOM describes a
*resolved* tree and usually carries no declared ranges, so an imported SBOM is analysed
in the lockfile-resident scenario; the interface says so rather than quietly pretending
otherwise.

    python sbom.py examples/demo-showcase.cyclonedx.json

**Fail a build on blast radius.** The same engine with no interface:

    python gate.py --package ms --max-exposure 10
    python gate.py --worst 5 --max-apps 12 --json

Exit code 0 within policy, 1 breached, 2 could not run — so it drops straight into CI.

## Data

Resolved dependency graphs come from the public [deps.dev](https://deps.dev) API (no
authentication required), which aggregates package metadata across registries and
carries the declared requirement range on every edge — the field this whole model
depends on. Advisories come from [OSV.dev](https://osv.dev) and maintainer counts from
the npm registry.

deps.dev's dependents endpoint returns only a *count* of dependent packages, not a
walkable list. Reverse edges are therefore constructed by inverting the portfolio
corpus. This is a deliberate design choice rather than a workaround: blast radius is
only meaningful relative to a defined set of applications, which in production is the
customer's own repositories. The corpus is defined in `seeds.txt` and stated on screen
rather than implied to be the whole ecosystem.

## What this does not claim

Reachability is not exploitability. This models whether malicious code reaches a build,
not whether a vulnerable function is ever called. Call-graph reachability is the honest
next phase. The interface says this too, in the same words.

## Files

    seeds.txt        the corpus - one application per line
    fetch.py         downloads dependency graphs, caches to cache.db
    build.py         builds the graph, writes graph.json and critical.json
    engine.py        propagation, semver gating, mitigation, pin fragility
    app.py           the interface
    brief.py         renders a one-page incident brief for whoever does the upgrade
    sbom.py          CycloneDX / SPDX import
    gate.py          CI policy gate
    enrich.py        optional OSV advisory and maintainer enrichment
    test_engine.py   regression tests
    examples/        a sample SBOM to try the upload path

`graph.json` is plain JSON rather than a pickle: loading the corpus must not be able to
execute code, least of all in a supply-chain security tool.

## Licence

MIT — see `LICENSE`.
