# Setup guide — from nothing to a working demo

Written assuming you have never run a Python script. Follow it in order. Do not skip.
Every command goes in **Terminal** (Mac) or **PowerShell** (Windows).

---

## Step 1 — Install Python (15 minutes)

### Mac

Open Terminal (Cmd+Space, type "Terminal", Enter). Type:

```
python3 --version
```

If it prints `Python 3.11.x` or higher, skip to Step 2. If not, install Homebrew, then
Python:

```
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
brew install python@3.12
```

### Windows

Download Python 3.12 from python.org. During installation, **tick "Add Python to PATH"**
on the first screen. This is the step everyone misses and it causes every later error.

Open PowerShell and verify:

```
python --version
```

> Throughout this guide, Mac users type `python3` and `pip3`.
> Windows users type `python` and `pip`. Everything else is identical.

---

## Step 2 — Put the project somewhere

Move the `blast-radius` folder to your Desktop. Then:

```
cd ~/Desktop/blast-radius          # Mac
cd $HOME\Desktop\blast-radius      # Windows
```

Check you are in the right place with `ls` (Mac) or `dir` (Windows). You should see
`app.py`, `engine.py`, `fetch.py`, `build.py`, `seeds.txt`, `requirements.txt`. If you
see nothing, you are in the wrong folder. Do not continue until this works.

---

## Step 3 — Install the five libraries

```
pip3 install -r requirements.txt
```

Takes 2–3 minutes. Ends with `Successfully installed ...`.

**If you get "externally-managed-environment"** (common on Mac with Homebrew), add
`--break-system-packages`. **If `pip3` is not found**, use `python3 -m pip install -r
requirements.txt`.

| Library | Job |
|---|---|
| `networkx` | holds the dependency graph and walks it |
| `node-semver` | decides whether a version range accepts a version — the core of the idea |
| `streamlit` | turns a Python file into a web interface |
| `pyvis` | draws the interactive graph |
| `pandas` | the small tables and the bar chart |

---

## Step 4 — The data is already here

`cache.db`, `records.json`, `graph.json` and `critical.json` ship with the project, so
**you can skip straight to Step 6 and the demo will work.**

Only re-run the download if you change `seeds.txt`:

```
python3 fetch.py
```

This takes 20–60 minutes on a cold cache. It is safe to interrupt and re-run: every
successful response is cached, and failures are cached *with their HTTP status*, so a
404 is remembered as final while a timeout is retried next time.

Some packages print `HTTP 404 ... trying an older release`. That is normal and handled —
deps.dev does not have a resolved graph for every version, so the script walks back
through older releases until one resolves.

---

## Step 5 — Build the graph

```
python3 build.py
```

Prints:

```
Applications      : 121
Package-versions  : 2,671
Dependency edges  : 5,023
Distinct packages : 2,255
```

**Look at the "most depended-upon" list.** You should recognise the names —
`tslib`, `debug`, `semver`, `@types/node`. If the top of that list is obscure, something
went wrong in Step 4.

Then it ranks blast radius at both scopes, which takes a couple of seconds:

```
 apps   now   held  package
   17    26      9  ms (14.0% exposure)
   15    23      8  debug (12.4% exposure)
   13    13      0  es-errors (10.7% exposure)
```

- **apps** — applications reached if the package ships a malicious *new* release.
- **now** — applications reached if the version already in your tree is the malicious one.
- **held** — the gap: applications a version pin is currently holding back.

Optionally add advisory and maintainer data (needs internet, takes about a minute):

```
python3 enrich.py
```

---

## Step 6 — Run the interface

```
streamlit run app.py
```

Your browser opens at `localhost:8501`. If it does not, copy the URL from the terminal.

To stop it: press `Ctrl+C` in the terminal.

---

## Step 7 — Check it is behaving

```
python3 test_engine.py
```

24 tests, no network, about a second. Every one of them corresponds to a specific claim
the interface makes. If they all pass, the numbers on screen are the numbers the
simulation produced.

---

## The demo, in order

These are the beats. Rehearse them until you do not need this page.

1. **Open on the risk map.** "Before we pick anything, the system has already ranked
   every package by how much of the portfolio sits downstream of it."

2. **Point at the advisory panel.** "OSV.dev reports zero known vulnerabilities against
   the forty most critical packages here. A scanner shows a clean board. Now watch."

3. **Simulate `ms`.** Default scenario, default settings.
   - 17 of 121 applications exposed, 14.0%, within 5 hops.
   - 9 more shielded by pins.
   - 65 package-versions carry it.

4. **Let the animation play.** Ground zero is the centre; each ring out is one hop. The
   camera opens tight and pulls back as each ring lands. Point out that several solid
   edges are *redundant routes* — the same application reached twice, which is why
   cutting one link often saves nobody.

5. **Click an application (a square) on an outer ring.** Its exact route back to the
   centre lights white and everything else fades. "Out of seventy-five packages, this
   is the only chain that matters for this service."

6. **Click a shielded (blue) node.** "This one is not safe, it is lagged. Its pin is the
   only thing holding the compromise back."

7. **Open the Fragile pins tab.** "And here is what that pin is worth: widen this single
   line and this application is exposed immediately. No attacker action required."

8. **Point at Fix these first.** "17 exposed down to 3 after three upgrades. That number
   is not arithmetic — we patched each package in the graph and ran the propagation
   again. It is the difference between two simulations."

9. **Switch to 'Already in your tree'.** 26 applications, 21.5%, nothing shielded.
   "Same package, different question: this is what it looks like if the malicious code
   is already in your lockfile."

10. **Hit a real-incident preset — `colors`.** One application. "This is a package that
    was genuinely sabotaged in 2022 and made the news. It reaches one service here.
    `ms`, which nobody has heard of and which has never been attacked, reaches
    seventeen. Severity does not predict blast radius. Position does."

11. **Download the incident brief.** "And the person who has to do the upgrade gets this,
    not a screenshot."

12. **Show the CI gate** in a terminal if you have time:
    `python3 gate.py --package ms --max-exposure 10` → exits 1.

Write down the exact numbers you see. **Do not round them up or invent them** — if the
corpus is rebuilt they may shift slightly, and the screen is the source of truth.

---

## What to say when a judge asks how it works

Six sentences. You must be able to say them without notes.

1. We fetch the resolved dependency tree for each of 121 applications from deps.dev and
   cache it locally, so the demo runs offline.
2. We merge them into one directed graph where an edge means "this package depends on
   that package", and every edge stores every declared version range.
3. We reverse the graph, so we can walk from a compromised package **upward** to
   everything that depends on it.
4. At each hop we check whether the parent's declared range would actually accept the
   version it would have to take — the malicious release at the origin, and the release
   an intermediate must publish to pass the compromise on. `^4.2.0` accepts `4.2.1` and
   it flows; an exact pin `4.2.0` blocks it, which is why a pinned dependency is lagged
   rather than safe.
5. Blast radius is then a count: how many of our applications are reachable through
   admitting routes.
6. To rank fixes we patch each candidate package in the graph and **re-run the whole
   propagation**, so the reduction we show is the measured difference between two
   simulations, not an assumption that cutting one route saves an application that had
   two.

### The four questions you will definitely get

**"Why not just use CVSS?"**
CVSS scores a package in isolation. A moderate bug in a package sitting under a third of
our services matters more than a critical bug in something nothing imports. Risk is a
property of position in the graph, not of the package alone. And in this corpus OSV
reports zero advisories against our forty most critical packages — the structural risk is
real whether or not anyone has filed a CVE.

**"Your graph isn't the whole npm ecosystem."**
Correct, and deliberately so. We analyse a defined corpus that we state on screen. In
production that corpus is the customer's own repositories, which is the only universe
that matters to them — that is what the SBOM upload is for. We report coverage rather
than implying completeness.

**"Reachable isn't the same as exploitable."**
Agreed, and we say so on the page. We model whether malicious code reaches a build, not
whether a vulnerable function is actually called. Call-graph reachability is the honest
next phase, and it's on our roadmap slide.

**"How do you know your mitigation numbers are right?"**
Because we do not compute them, we measure them. Each recommended upgrade is applied to
the graph and the propagation is re-run. `test_engine.py` asserts that the number we
print equals an independent re-simulation, on both a synthetic graph and the real
corpus.

---

## If something breaks

| Error | Fix |
|---|---|
| `command not found: python3` | Python isn't installed or isn't on PATH. Redo Step 1. |
| `No module named streamlit` | Step 3 didn't finish. Run it again and read the output. |
| `ERROR: seeds.txt not found` | You are in the wrong folder. Redo Step 2. |
| `records.json missing` | Run `python3 fetch.py` first. |
| `No graph found` in the browser | Run `python3 build.py`, then restart the app. |
| `externally-managed-environment` | Add `--break-system-packages` to the pip command. |
| The graph panel is blank | Reload the page. The renderer is inlined, so this is not a network problem. |

If you hit anything else, paste the **entire** red error message. The last three lines
are the ones that matter.

---

## Recording the demo

1. Run `python3 build.py` and `streamlit run app.py` **before** you start recording, so
   everything is warm.
2. **Turn off your wifi.** The interface runs entirely from the local cache and the
   graph renderer is inlined into the page — nothing is fetched at runtime. Proving this
   on camera is a strength, and it guarantees nothing fails live.
3. Zoom the browser to 110% so the numbers are legible in a compressed video.
4. Hide your bookmarks bar. Check the terminal prompt doesn't show your name or college —
   institutional identity in submitted media is a point deduction under §9.1 Tier 2.
5. Record the screen in one clean take. Re-record until it is perfect. Never do this live.

---

## Publishing the repository

§6.4 makes the prototype bonus conditional on a **publicly accessible GitHub
repository** during evaluation, so this is not optional.

Git is not installed on the machine this was built on. Install it from
[git-scm.com](https://git-scm.com/downloads), reopen your terminal, then from the
project folder:

```
git init
git add -A
git status --short
```

**Read that file list before committing.** `.gitignore` already excludes `__pycache__/`,
`tmp/` and `graph.pkl`; `tmp/` holds local scratch files that must not end up in a
public repository. If anything unexpected appears in the list, stop and fix
`.gitignore` first.

`cache.db` (14 MB), `records.json`, `graph.json` and `critical.json` **are** committed
on purpose: they are what let a judge clone the repository and run the demo offline
without waiting an hour for `fetch.py`. Say so in the README rather than letting it look
accidental — it already does.

```
git commit -m "Blast radius: semver-gated supply-chain propagation analysis"
git branch -M main
git remote add origin https://github.com/<you>/<repo>.git
git push -u origin main
```

Then open the repository URL in an **incognito window**. If it asks you to sign in, it
is private and the prototype bonus is forfeit under §6.4.

Check the commit author too: `git config user.email` must not reveal your institute.

---

## Before you submit

- [ ] `python3 test_engine.py` passes.
- [ ] The GitHub repository is **public** — check the URL in an incognito window.
- [ ] `tmp/` is not committed (it is in `.gitignore`; delete the folder if it exists).
- [ ] No institute name, logo or identifying background in the deck, the video, or a
      visible terminal path.
- [ ] The presentation uses the official template from the portal, exported as **PDF**,
      named `TeamID_TeamName_ProblemStatementID`.
- [ ] The video is ≤ 3 minutes (prototype included), every registered member appears,
      and the link opens in an incognito window without an access request.
