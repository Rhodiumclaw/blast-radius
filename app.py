"""
Step 3: the interface.

    streamlit run app.py

Everything below reads the local cache. There is no network call in this file,
so the whole thing runs with the wifi switched off - including the graph, whose
rendering library is inlined into the page rather than pulled from a CDN.
"""
from __future__ import annotations

import json
import math
import os
import re

import pandas as pd
import streamlit as st
import streamlit.components.v1 as components
from pyvis.network import Network

from brief import incident_brief
from engine import (SCOPE_NAME, SCOPE_VERSION, GraphError, build_graph,
                    bump_patch, detonate, explain_path, load_graph, node_name,
                    node_version, nodes_named, pin_fragility, pins_for_app,
                    rank_critical, rank_mitigations, shielded_route)
from sbom import SbomError, load_sbom

st.set_page_config(page_title="Blast radius", page_icon="💥", layout="wide")

# Presentation layer. Static CSS only - no data reaches it, so there is nothing
# here that a package name could influence. Every motion is suppressed under
# prefers-reduced-motion at the bottom of the sheet.
_PAGE_STYLE = """
<style>
@keyframes blastRise {
  from { opacity: 0; transform: translateY(10px); }
  to   { opacity: 1; transform: none; }
}
@keyframes blastSweep {
  from { background-position: 200% 0; }
  to   { background-position: -200% 0; }
}
@keyframes blastBreathe {
  0%, 100% { box-shadow: 0 0 0 0 rgba(232, 51, 109, 0.00); }
  50%      { box-shadow: 0 0 0 6px rgba(232, 51, 109, 0.07); }
}

.stApp { background: radial-gradient(1200px 600px at 18% -8%,
         rgba(232,51,109,0.07), transparent 62%), #0E1218; }

/* headings get a short accent rule, so sections read as sections */
h2, h3 { position: relative; padding-left: 14px; }
h2::before, h3::before {
  content: ""; position: absolute; left: 0; top: 0.18em; bottom: 0.18em;
  width: 3px; border-radius: 2px;
  background: linear-gradient(180deg, #E8336D, #F26A4B);
}
h1 { letter-spacing: -0.02em; }

/* blocks arrive rather than appear */
[data-testid="stVerticalBlock"] > [data-testid="stElementContainer"] {
  animation: blastRise 0.42s cubic-bezier(0.16, 0.84, 0.44, 1) both;
}
[data-testid="stVerticalBlock"] > [data-testid="stElementContainer"]:nth-child(1) { animation-delay: 0.02s; }
[data-testid="stVerticalBlock"] > [data-testid="stElementContainer"]:nth-child(2) { animation-delay: 0.05s; }
[data-testid="stVerticalBlock"] > [data-testid="stElementContainer"]:nth-child(3) { animation-delay: 0.08s; }
[data-testid="stVerticalBlock"] > [data-testid="stElementContainer"]:nth-child(4) { animation-delay: 0.11s; }
[data-testid="stVerticalBlock"] > [data-testid="stElementContainer"]:nth-child(n+5) { animation-delay: 0.14s; }

/* metrics as instrument readouts */
[data-testid="stMetric"] {
  background: linear-gradient(180deg, rgba(255,255,255,0.035), rgba(255,255,255,0.012));
  border: 1px solid #232A36;
  border-left: 3px solid #E8336D;
  border-radius: 10px;
  padding: 12px 16px;
  transition: transform 0.22s cubic-bezier(0.16,0.84,0.44,1),
              border-color 0.22s ease, box-shadow 0.22s ease;
}
[data-testid="stMetric"]:hover {
  transform: translateY(-2px);
  border-color: #3A4454;
  box-shadow: 0 10px 26px rgba(0,0,0,0.38);
}
[data-testid="stMetricValue"] {
  font-variant-numeric: tabular-nums;
  letter-spacing: -0.02em;
}
[data-testid="stMetricLabel"] {
  text-transform: uppercase;
  letter-spacing: 0.08em;
  font-size: 0.68rem !important;
  opacity: 0.72;
}

/* buttons */
.stButton > button, [data-testid="stDownloadButton"] > button {
  border-radius: 8px;
  transition: transform 0.16s ease, box-shadow 0.2s ease, border-color 0.2s ease;
}
.stButton > button:hover, [data-testid="stDownloadButton"] > button:hover {
  transform: translateY(-1px);
  box-shadow: 0 6px 18px rgba(0,0,0,0.34);
}
.stButton > button:active { transform: translateY(0); }
.stButton > button[kind="primary"] {
  background: linear-gradient(135deg, #E8336D, #C4255A);
  border: none;
  animation: blastBreathe 3.4s ease-in-out infinite;
}

/* bordered containers, tabs, tables */
[data-testid="stVerticalBlockBorderWrapper"] {
  border-radius: 10px;
  transition: border-color 0.22s ease, background 0.22s ease;
}
[data-testid="stVerticalBlockBorderWrapper"]:hover { border-color: #3A4454; }
.stTabs [data-baseweb="tab"] { transition: color 0.2s ease; }
.stTabs [data-baseweb="tab-highlight"] {
  background: linear-gradient(90deg, #E8336D, #F26A4B);
}
[data-testid="stDataFrame"] { border-radius: 10px; overflow: hidden; }
[data-testid="stAlert"] { border-radius: 10px; border-left-width: 3px; }
[data-testid="stSidebar"] { border-right: 1px solid #1D242F; }
[data-testid="stExpander"] details { border-radius: 10px; }

/* the loading shimmer Streamlit shows while a rerun is in flight */
[data-testid="stSkeleton"] {
  background: linear-gradient(90deg, #161B24 25%, #1E2531 50%, #161B24 75%);
  background-size: 200% 100%;
  animation: blastSweep 1.3s linear infinite;
}

@media (prefers-reduced-motion: reduce) {
  *, *::before, *::after {
    animation-duration: 0.001ms !important;
    animation-iteration-count: 1 !important;
    transition-duration: 0.001ms !important;
  }
}
</style>
"""
st.markdown(_PAGE_STYLE, unsafe_allow_html=True)

ORIGIN = "#E8336D"                                    # the compromised package
HOP = ["#F26A4B", "#F0A04B", "#D9C77E", "#9BB8A6"]    # fades with distance
LATENT = "#4F6B8A"                                    # pinned, not yet exposed
CANVAS = "#151922"
INK = "#C9D1D9"

CRITICAL_FILE = "critical.json"
ENRICH_FILE = "enrich.json"

# Packages in this corpus that have actually been compromised or sabotaged in
# the wild. Nothing here is hypothetical - each one is a published incident.
INCIDENTS = {
    "colors": ("2022", "Maintainer deliberately published an infinite-loop payload, "
                       "breaking thousands of builds overnight."),
    "faker": ("2022", "Sabotaged by its own maintainer in the same week as colors."),
    "rc": ("2021", "Maintainer account taken over; malicious versions published "
                   "alongside coa and ua-parser-js."),
    "eslint-scope": ("2018", "Maintainer credentials stolen; a release was published "
                             "that exfiltrated npm tokens."),
    "is-promise": ("2020", "A malformed publish broke a large slice of the ecosystem "
                           "in minutes - the same blast radius, different cause."),
    "minimist": ("2021", "Prototype-pollution advisory reaching deep into tooling "
                         "dependency trees."),
    "event-stream": ("2018", "A new maintainer added a malicious transitive dependency "
                             "targeting a specific wallet."),
    "ua-parser-js": ("2021", "Account takeover; malicious versions shipped a "
                             "cryptominer and a credential stealer."),
    "node-ipc": ("2022", "Protestware added by the maintainer, overwriting files on "
                         "machines in particular countries."),
}


# ---------------------------------------------------------------------------
# Client-side animation, injected into the pyvis-generated HTML.
#
# pyvis declares `nodes`, `edges` and `network` as script-scope globals and
# calls drawGraph() synchronously, so a script appended after it drives the same
# live vis-network instance. All data crosses into JS as one JSON blob rather
# than by string substitution, so a package name or version range can never be
# read as code or markup.
# ---------------------------------------------------------------------------
_CONTROLS_HTML = """
<div id="blast-controls" style="font-family:'Source Sans Pro',sans-serif;color:#C9D1D9;
     background:#10141b;padding:8px 16px;display:flex;align-items:center;gap:14px;
     border-bottom:1px solid #2b313b;flex-wrap:wrap;">
  <button id="blast-play" type="button" style="cursor:pointer;background:#E8336D;border:none;
          color:white;padding:6px 16px;border-radius:4px;font-weight:600;font-size:0.85rem;">
    &#9654; Play</button>
  <button id="blast-restart" type="button" style="cursor:pointer;background:#2b313b;
          border:1px solid #3d4657;color:#C9D1D9;padding:6px 14px;border-radius:4px;
          font-size:0.85rem;">&#8635; Restart</button>
  <label style="font-size:0.8rem;display:flex;align-items:center;gap:7px;">Speed
    <span style="opacity:0.55;font-size:0.72rem;">slow</span>
    <input id="blast-speed" type="range" min="200" max="2000" step="100" value="1400"
           style="vertical-align:middle;" aria-label="Animation speed">
    <span style="opacity:0.55;font-size:0.72rem;">fast</span>
  </label>
  <div id="blast-status" style="margin-left:auto;font-size:0.85rem;opacity:0.85;">Ready</div>
</div>
<div id="blast-infopanel" style="display:none;position:absolute;top:64px;right:16px;
     max-width:270px;background:#1b212c;border:1px solid #3d4657;border-radius:8px;
     padding:12px 14px;color:#C9D1D9;font-size:0.82rem;line-height:1.5;
     box-shadow:0 6px 20px rgba(0,0,0,0.45);z-index:1000;"></div>
"""

_ANIMATION_JS = """
<script>
(function(){
  var CFG = window.__BLAST__ || {};

  function hexToRgba(hex, alpha){
    hex = String(hex).replace("#", "");
    var n = parseInt(hex, 16);
    return "rgba(" + ((n>>16)&255) + "," + ((n>>8)&255) + "," + (n&255) + "," + alpha + ")";
  }

  var statusEl = document.getElementById("blast-status");
  function setStatus(text){ if (statusEl) statusEl.textContent = text; }

  function whenReady(fn){
    var tries = 0;
    var timer = setInterval(function(){
      tries++;
      if (typeof network !== "undefined" && network && typeof nodes !== "undefined") {
        clearInterval(timer);
        fn();
      } else if (tries > 80) {
        clearInterval(timer);
        setStatus("Graph library did not load - reload the page");
      }
    }, 100);
  }

  whenReady(function(){
    var TARGETS = CFG.targets || [];
    var TARGET_SET = {};
    TARGETS.forEach(function(id){ TARGET_SET[id] = true; });
    var ORIGIN_COLOR = CFG.origin || "#E8336D";
    var LATENT_COLOR = CFG.latent || "#4F6B8A";
    var HOP_COLORS = CFG.hops || ["#F26A4B"];
    var MAX_HOP = CFG.maxHop || 0;
    var RINGS = CFG.rings || [];
    var ROUTES = CFG.routes || {};
    var LAYERED = CFG.layout === "rings";
    var REDUCED = window.matchMedia
      && window.matchMedia("(prefers-reduced-motion: reduce)").matches;

    var allNodes = nodes.get();
    var allEdges = edges.get();
    var hopOf = {};
    allNodes.forEach(function(n){
      hopOf[n.id] = (typeof n.hop === "number" && n.hop >= 0) ? n.hop : null;
    });

    function hopColour(h){
      return HOP_COLORS[Math.min(Math.max(h, 1) - 1, HOP_COLORS.length - 1)];
    }

    function hideAll(){
      nodes.update(allNodes.map(function(n){
        return {id: n.id, hidden: !TARGET_SET[n.id]};
      }));
      edges.update(allEdges.map(function(e){
        return {id: e.id, hidden: !(e.kind === "infection" && e.hop === 0)};
      }));
    }

    // --- overlay: origin halo, arrival rings, travelling pulses --------------
    var halos = {};
    var pulses = [];
    var shocks = [];
    var rafId = null;
    // Tracked as the reveal happens. Recomputing it by scanning every node each
    // frame cost a DataSet lookup per node at 60fps for no reason.
    var revealedHop = 0;

    function shockwave(hop){
      if (REDUCED || !LAYERED) return;
      var ring = null;
      RINGS.forEach(function(r){ if (r.level === hop) ring = r; });
      if (!ring || !ring.radius) return;
      shocks.push({start: Date.now(), dur: 700, to: ring.radius,
                   colour: HOP_COLORS[Math.min(Math.max(hop, 1) - 1,
                                               HOP_COLORS.length - 1)]});
      ensureFrames();
    }

    function arrivalRing(nodeId, colour){
      if (REDUCED) return;
      halos[nodeId] = {end: Date.now() + 750, dur: 750, colour: colour};
      ensureFrames();
    }
    function fireEdgePulse(fromId, toId, colour){
      if (REDUCED) return;
      var pos = network.getPositions([fromId, toId]);
      if (!pos[fromId] || !pos[toId]) return;
      pulses.push({from: pos[fromId], to: pos[toId], start: Date.now(),
                   dur: 550, colour: colour});
      ensureFrames();
    }

    // --- ring guides, drawn behind everything -------------------------------
    // The distance rings are the point of the picture, so they are part of the
    // drawing rather than something the reader has to infer from the colours.
    // The canvas context handed to these hooks is already transformed into graph
    // space, so anything drawn in raw units shrinks as the camera pulls back - a
    // 4-unit pulse ends up a single pixel wide once the view is zoomed out to
    // fit the whole blast. Everything below is therefore divided by the current
    // scale, which keeps line weights, halos and labels a constant size on
    // screen no matter how far out the camera has travelled.
    function px(value){
      var s = network.getScale();
      return value / (s && s > 0 ? s : 1);
    }

    network.on("beforeDrawing", function(ctx){
      if (!LAYERED || !RINGS.length) return;
      ctx.save();
      RINGS.forEach(function(ring){
        if (!ring.radius) return;
        var reached = ring.level <= revealedHop;
        ctx.beginPath();
        ctx.arc(0, 0, ring.radius, 0, 2 * Math.PI);
        ctx.strokeStyle = reached ? "rgba(232,51,109,0.22)" : "rgba(120,132,150,0.13)";
        ctx.lineWidth = px(reached ? 1.6 : 1.1);
        ctx.setLineDash(reached ? [] : [px(4), px(6)]);
        ctx.stroke();
        ctx.setLineDash([]);
        // a hop split across several bands gets a faint outer edge too, so the
        // band group still reads as one hop rather than as several
        if (ring.bands && ring.bands > 1) {
          ctx.beginPath();
          ctx.arc(0, 0, ring.radius + (ring.bands - 1) * 58, 0, 2 * Math.PI);
          ctx.strokeStyle = reached ? "rgba(232,51,109,0.10)"
                                    : "rgba(120,132,150,0.07)";
          ctx.lineWidth = px(1);
          ctx.setLineDash([px(3), px(7)]);
          ctx.stroke();
          ctx.setLineDash([]);
        }
        ctx.fillStyle = reached ? "rgba(232,51,109,0.62)" : "rgba(138,147,163,0.42)";
        ctx.font = "600 " + px(12).toFixed(1) + "px 'Source Sans Pro', sans-serif";
        ctx.textAlign = "center";
        ctx.fillText("hop " + ring.level, 0, -ring.radius - px(10));
      });
      ctx.restore();
    });

    network.on("afterDrawing", function(ctx){
      var now = Date.now();
      if (playing && !REDUCED) {
        TARGETS.forEach(function(id){
          var pos = network.getPositions([id])[id];
          if (!pos) return;
          var pulse = 0.5 + 0.5 * Math.sin(now / 260);
          ctx.beginPath();
          ctx.arc(pos.x, pos.y, px(22 + pulse * 9), 0, 2 * Math.PI);
          ctx.strokeStyle = hexToRgba(ORIGIN_COLOR, 0.15 + 0.5 * pulse);
          ctx.lineWidth = px(3);
          ctx.stroke();
        });
      }
      Object.keys(halos).forEach(function(id){
        var halo = halos[id];
        if (now > halo.end) { delete halos[id]; return; }
        var pos = network.getPositions([id])[id];
        if (!pos) return;
        var frac = 1 - (halo.end - now) / halo.dur;
        ctx.beginPath();
        ctx.arc(pos.x, pos.y, px(9 + frac * 26), 0, 2 * Math.PI);
        ctx.strokeStyle = hexToRgba(halo.colour, (1 - frac) * 0.9);
        ctx.lineWidth = px(2.5);
        ctx.stroke();
      });
      shocks = shocks.filter(function(s){ return now < s.start + s.dur; });
      shocks.forEach(function(s){
        var frac = (now - s.start) / s.dur;
        var eased = 1 - Math.pow(1 - frac, 3);
        ctx.beginPath();
        ctx.arc(0, 0, s.to * eased, 0, 2 * Math.PI);
        ctx.strokeStyle = hexToRgba(s.colour, (1 - frac) * 0.5);
        ctx.lineWidth = px(2.5 * (1 - frac) + 0.6);
        ctx.stroke();
      });

      pulses = pulses.filter(function(p){ return now < p.start + p.dur; });
      pulses.forEach(function(p){
        var frac = (now - p.start) / p.dur;
        var eased = frac * frac * (3 - 2 * frac);   // ease in and out of the hop
        ctx.beginPath();
        ctx.arc(p.from.x + (p.to.x - p.from.x) * eased,
                p.from.y + (p.to.y - p.from.y) * eased, px(4.5), 0, 2 * Math.PI);
        ctx.fillStyle = p.colour;
        ctx.shadowColor = p.colour;
        ctx.shadowBlur = px(10);
        ctx.fill();
        ctx.shadowBlur = 0;
      });
    });

    // One loop drives everything: the hop clock, the staggered reveal and the
    // overlay. Frames are only burned while something is genuinely moving.
    function ensureFrames(){
      if (rafId !== null) return;
      (function tickFrame(){
        var now = Date.now();
        advance(now);
        drainPending(now);
        if (awaitingFinalFrame && pending.length === 0) {
          awaitingFinalFrame = false;
          frameTo(null);          // everything is on screen: frame all of it
        }
        var busy = playing || pending.length > 0 || pulses.length > 0
                   || shocks.length > 0 || Object.keys(halos).length > 0;
        network.redraw();
        rafId = busy ? requestAnimationFrame(tickFrame) : null;
      })();
    }

    // The camera opens tight on ground zero and eases outward as each ring
    // lands, so the blast grows into the frame instead of the frame being
    // wide and mostly empty from the first second.
    // Margin in graph units for what the ring radius alone does not cover: the
    // node bodies, the applications riding outside their band, their labels and
    // the "hop N" caption drawn above each ring.
    var FRAME_MARGIN = 110;

    function ringRadius(upTo){
      var radius = 0;
      RINGS.forEach(function(r){
        if (upTo === null || r.level <= upTo) {
          radius = Math.max(radius, r.radius + ((r.bands || 1) - 1) * 58);
        }
      });
      return radius;
    }

    function frameTo(hop){
      if (!network.moveTo) return;
      var duration = REDUCED ? 0 : 620;
      var animation = REDUCED ? false
        : {duration: duration, easingFunction: "easeInOutQuad"};

      if (!LAYERED || !RINGS.length) {
        try { network.fit({animation: animation}); } catch (e) {}
        return;
      }
      var radius = ringRadius(hop);
      var height = (CFG.panel || 780);
      // 0.34 rather than a tight fit: the picture should sit inside the panel
      // with room to breathe, not press against its edges.
      var scale = radius > 0 ? (height * 0.34) / (radius + FRAME_MARGIN) : 1.4;
      scale = Math.max(0.05, Math.min(scale, 1.9));
      try {
        network.moveTo({position: {x: 0, y: 0}, scale: scale,
                        animation: animation});
      } catch (e) {}
    }

    // --- hop-by-hop reveal --------------------------------------------------
    // A hop is not dumped on screen all at once. Its members are queued, sorted
    // by angle around the ring, and released a few milliseconds apart, so the
    // hop arrives as a wave sweeping round the circle behind the shockwave
    // instead of as a single pop.
    var pending = [];
    var edgesFrom = {};
    allEdges.forEach(function(e){
      if (e.kind !== "infection") return;
      (edgesFrom[e.from] = edgesFrom[e.from] || []).push(e);
    });

    function angleOf(id){
      var p = network.getPositions([id])[id];
      return p ? Math.atan2(p.y, p.x) : 0;
    }

    function queueReveal(members, colour, span){
      if (!members.length) return;
      var ordered = members.slice();
      if (LAYERED && !REDUCED) {
        ordered.sort(function(a, b){ return angleOf(a.id) - angleOf(b.id); });
      }
      var gap = (REDUCED || ordered.length < 2) ? 0 : span / ordered.length;
      var now = Date.now();
      ordered.forEach(function(n, i){
        pending.push({id: n.id, at: now + i * gap, colour: colour});
      });
      ensureFrames();
    }

    function drainPending(now){
      if (!pending.length) return;
      var nodeUpdates = [], edgeUpdates = [], still = [];
      for (var i = 0; i < pending.length; i++) {
        var item = pending[i];
        if (item.at > now) { still.push(item); continue; }
        nodeUpdates.push({id: item.id, hidden: false});
        if (hopOf[item.id] !== null && hopOf[item.id] > revealedHop) {
          revealedHop = hopOf[item.id];
        }
        arrivalRing(item.id, item.colour);
        (edgesFrom[item.id] || []).forEach(function(e){
          if (e.hop > step) return;
          edgeUpdates.push({id: e.id, hidden: false});
          // the compromise travels against the dependency arrow: from the
          // already-infected dependency up to the dependent that takes it
          fireEdgePulse(e.to, e.from, item.colour);
        });
      }
      pending = still;
      if (nodeUpdates.length) nodes.update(nodeUpdates);
      if (edgeUpdates.length) edges.update(edgeUpdates);
    }

    function revealHop(h){
      shockwave(h);
      queueReveal(allNodes.filter(function(n){ return hopOf[n.id] === h; }),
                  hopColour(h), Math.min(interval() * 0.72, 900));
    }

    function revealShielded(){
      queueReveal(allNodes.filter(function(n){ return hopOf[n.id] === null; }),
                  LATENT_COLOR, 700);
      var edgeUpdates = [];
      allEdges.forEach(function(e){
        if (e.kind === "blocked" || e.kind === "shield") {
          edgeUpdates.push({id: e.id, hidden: false});
        }
      });
      if (edgeUpdates.length) edges.update(edgeUpdates);
    }

    // --- click a node for the detail ----------------------------------------
    // Built as DOM nodes with textContent rather than assembled HTML: package
    // names and version ranges are attacker-influenced data in the very threat
    // model this page is about, so they are never parsed as markup.
    var infoPanel = document.getElementById("blast-infopanel");

    function line(text, style){
      var el = document.createElement("div");
      el.textContent = text;
      if (style) el.setAttribute("style", style);
      return el;
    }

    function showInfo(nodeId){
      var n = nodes.get(nodeId);
      if (!n || !infoPanel) return;
      infoPanel.replaceChildren();

      infoPanel.appendChild(line(n.pkgName,
        "font-weight:700;font-size:0.92rem;margin-bottom:6px;"));
      infoPanel.appendChild(line("Version: " + n.pkgVersion));
      infoPanel.appendChild(line(n.isApp ? "Application in this portfolio"
                                         : "Intermediate package"));

      if (TARGET_SET[nodeId]) {
        infoPanel.appendChild(line("\\u25CF Compromised package",
          "margin-top:6px;font-weight:600;color:" + ORIGIN_COLOR));
        if (n.simVersion) {
          infoPanel.appendChild(line("Simulated malicious version " + n.simVersion));
        }
        if (n.directDeps != null) {
          infoPanel.appendChild(
            line(n.directDeps + " package(s) depend on it directly"));
        }
      } else if (hopOf[nodeId] === null) {
        infoPanel.appendChild(line("\\u25CF Shielded \\u2014 not yet exposed",
          "margin-top:6px;font-weight:600;color:" + LATENT_COLOR));
        (n.pinNotes || []).forEach(function(note){
          infoPanel.appendChild(line(note, "margin-top:4px;"));
        });
      } else {
        infoPanel.appendChild(
          line("\\u25CF Exposed \\u2014 hop " + hopOf[nodeId] + " from the origin",
               "margin-top:6px;font-weight:600;color:" + hopColour(hopOf[nodeId])));
        if (n.routes > 1) {
          infoPanel.appendChild(line(
            n.routes + " separate routes reach it \\u2014 cutting one is not enough"));
        }
      }

      var close = document.createElement("button");
      close.type = "button";
      close.textContent = "\\u2715 close";
      close.setAttribute("style", "margin-top:10px;cursor:pointer;background:none;"
        + "border:none;padding:0;color:#8a93a3;font-size:0.75rem;font:inherit;");
      close.addEventListener("click", function(){
        infoPanel.style.display = "none";
      });
      infoPanel.appendChild(close);
      infoPanel.style.display = "block";
    }

    // --- trace one route back to ground zero --------------------------------
    // Selecting a node answers "how would this reach me?" by lighting only the
    // chain that carries the compromise and dimming everything it never touched.
    var edgeKey = {};
    allEdges.forEach(function(e){ edgeKey[e.from + "\\u0000" + e.to] = e.id; });
    var tracing = false;

    function clearTrace(){
      if (!tracing) return;
      tracing = false;
      nodes.update(allNodes.map(function(n){
        return {id: n.id, opacity: 1, borderWidth: 1};
      }));
      edges.update(allEdges.map(function(e){
        return {id: e.id, color: e.color, width: e.width};
      }));
      setStatus(MAX_HOP > 0 ? "Hop " + Math.min(step, MAX_HOP) + " of " + MAX_HOP
                            : "Ready");
    }

    function traceTo(nodeId){
      var route = ROUTES[nodeId];
      if (!route || route.length < 2) { clearTrace(); return; }
      var onRoute = {}, usedEdge = {};
      route.forEach(function(id){ onRoute[id] = true; });
      for (var i = 0; i < route.length - 1; i++) {
        var id = edgeKey[route[i] + "\\u0000" + route[i + 1]];
        if (id !== undefined) usedEdge[id] = true;
      }
      tracing = true;
      nodes.update(allNodes.map(function(n){
        return {id: n.id, opacity: onRoute[n.id] ? 1 : 0.13,
                borderWidth: onRoute[n.id] ? 3 : 1};
      }));
      edges.update(allEdges.map(function(e){
        return usedEdge[e.id]
          ? {id: e.id, color: {color: "#FFFFFF", opacity: 1}, width: 3}
          : {id: e.id, color: {color: e.color, opacity: 0.07}, width: e.width};
      }));
      var node = nodes.get(nodeId);
      setStatus((node ? node.pkgName : "route") + " \\u2190 " + (route.length - 1)
                + " hop(s) back to the origin");
    }

    network.on("click", function(params){
      if (params.nodes && params.nodes.length) {
        showInfo(params.nodes[0]);
        traceTo(params.nodes[0]);
      } else {
        if (infoPanel) infoPanel.style.display = "none";
        clearTrace();
      }
    });

    // --- playback -----------------------------------------------------------
    var playBtn = document.getElementById("blast-play");
    var restartBtn = document.getElementById("blast-restart");
    var speedInput = document.getElementById("blast-speed");
    var step = 0, playing = false, finished = false, nextHopAt = 0;
    var awaitingFinalFrame = false;

    // The slider reads left-to-right as slow-to-fast, so its value is inverted
    // into the delay between hops. Using the raw value as the delay made the
    // control run backwards: dragging towards "fast" waited longer.
    var SPEED_MIN = 200, SPEED_MAX = 2000;
    function interval(){
      var v = parseInt(speedInput.value, 10);
      if (isNaN(v)) v = 1400;
      v = Math.max(SPEED_MIN, Math.min(SPEED_MAX, v));
      return (SPEED_MIN + SPEED_MAX) - v;
    }

    // The clock is driven from the animation frame rather than setInterval.
    // setInterval queues missed ticks and then fires them back to back after any
    // stall - a layout pass, a background tab, a slow repaint - which is what
    // made the blast appear to skip straight to the end. Checking elapsed time
    // once per frame can never run two hops in the same breath.
    function advance(now){
      if (!playing || now < nextHopAt) return;
      step++;
      if (step > MAX_HOP) {
        revealShielded();
        playing = false;
        finished = true;
        setStatus("Done \\u2014 " + MAX_HOP + " hop(s), shielded applications shown");
        playBtn.textContent = "\\u25B6 Replay";
        // Do not frame yet: the shielded ring is still arriving, and framing now
        // would fit the camera to a picture that is about to grow.
        awaitingFinalFrame = true;
        return;
      }
      revealHop(step);
      setStatus("Hop " + step + " of " + MAX_HOP);
      frameTo(step);
      nextHopAt = now + interval();
    }

    function reset(){
      playing = false; finished = false; step = 0; nextHopAt = 0;
      awaitingFinalFrame = false; revealedHop = 0;
      halos = {}; pulses = []; shocks = []; pending = [];
      clearTrace();
      hideAll();
      setStatus(MAX_HOP > 0 ? "Ready \\u2014 hop 0 of " + MAX_HOP
                            : "Nothing downstream to reach");
      playBtn.textContent = "\\u25B6 Play";
      frameTo(0);
      network.redraw();
    }

    function play(){
      if (playing) return;
      if (finished || step >= MAX_HOP) reset();
      playing = true;
      finished = false;
      playBtn.textContent = "\\u275A\\u275A Pause";
      // first hop lands promptly; the rest are paced by the slider
      nextHopAt = Date.now() + Math.min(interval() * 0.35, 260);
      ensureFrames();
    }

    function pause(){
      if (!playing) return;
      playing = false;
      playBtn.textContent = "\\u25B6 Resume";
    }

    playBtn.addEventListener("click", function(){ playing ? pause() : play(); });
    restartBtn.addEventListener("click", reset);
    speedInput.addEventListener("input", function(){
      if (playing) nextHopAt = Math.min(nextHopAt, Date.now() + interval());
    });

    network.once("stabilizationIterationsDone", function(){ frameTo(0); });

    reset();
    setTimeout(play, 460);
  });
})();
</script>
"""

# Anything the page would have to fetch at runtime. Stripped so the graph draws
# with the network cable pulled out - see the note in the README.
_REMOTE_SCRIPT = re.compile(
    r'<script[^>]*\ssrc\s*=\s*["\'](?:https?:|//|\.\./)[^"\']*["\'][^>]*>\s*</script>',
    re.IGNORECASE)
_REMOTE_LINK = re.compile(
    r'<link[^>]*\shref\s*=\s*["\'](?:https?:|//|\.\./)[^"\']*["\'][^>]*>',
    re.IGNORECASE)


def build_animated_html(net, config):
    """Wrap a pyvis network in the playback controls and make it self-contained."""
    html = net.generate_html(notebook=False)
    html = _REMOTE_SCRIPT.sub("", html)
    html = _REMOTE_LINK.sub("", html)
    # Escaped so the payload is inert as markup no matter what a package name or
    # version range contains. < etc. are valid JSON string escapes.
    blob = (json.dumps(config)
            .replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026"))
    payload = "<script>window.__BLAST__ = " + blob + ";</script>"
    html = html.replace("<body>", "<body>" + _CONTROLS_HTML, 1)
    html = html.replace("</body>", payload + _ANIMATION_JS + "</body>", 1)
    return html


# ---------------------------------------------------------------------------
# data loading
# ---------------------------------------------------------------------------

@st.cache_resource(show_spinner="Loading dependency graph...")
def load_bundled_corpus():
    try:
        G, app_roots = load_graph()
    except GraphError as exc:
        return {"error": str(exc)}
    if G is None:
        return None
    rankings, meta = {}, {}
    if os.path.exists(CRITICAL_FILE):
        with open(CRITICAL_FILE, "r", encoding="utf-8") as f:
            payload = json.load(f)
        rankings = payload.get("rankings") or {}
        meta = {k: v for k, v in payload.items() if k != "rankings"}
    if not rankings:
        rankings = {
            SCOPE_NAME: rank_critical(G, app_roots, scope=SCOPE_NAME, limit=40),
            SCOPE_VERSION: rank_critical(G, app_roots, scope=SCOPE_VERSION, limit=40),
        }
    return {"id": "bundled", "G": G, "app_roots": app_roots,
            "rankings": rankings, "meta": meta,
            "label": "Bundled portfolio", "ranges": True, "notes": []}


@st.cache_resource(show_spinner="Reading SBOM...")
def load_sbom_corpus(payloads):
    """payloads: tuple of (filename, bytes). Cached on the file contents."""
    records, notes, declared = [], [], 0
    for filename, raw in payloads:
        try:
            record, info = load_sbom(raw)
        except SbomError as exc:
            notes.append(f"{filename}: {exc}")
            continue
        records.append(record)
        declared += info["declared_ranges"]
        notes.append(f"{filename}: {info['format']}, {info['components']} components, "
                     f"{info['dependencies']} dependencies")
    if not records:
        return None
    G, app_roots = build_graph(records)
    rankings = {
        SCOPE_NAME: rank_critical(G, app_roots, scope=SCOPE_NAME, limit=40, pool=300),
        SCOPE_VERSION: rank_critical(G, app_roots, scope=SCOPE_VERSION, limit=40, pool=300),
    }
    return {"id": "sbom:" + str(hash(payloads)), "G": G, "app_roots": app_roots,
            "rankings": rankings, "meta": {}, "label": "Your SBOM",
            "ranges": declared > 0, "notes": notes}


@st.cache_resource(show_spinner=False)
def load_enrichment():
    if not os.path.exists(ENRICH_FILE):
        return None
    with open(ENRICH_FILE, "r", encoding="utf-8") as f:
        return json.load(f)


# ---------------------------------------------------------------------------
# graph rendering
# ---------------------------------------------------------------------------

def _ring_layout(nodes, down_edges, targets):
    """
    Ground zero at the centre, one ring per hop.

    Within a ring, nodes are ordered by the average angle of whatever they
    depend on in the ring below, which keeps a package near the thing that
    infected it and stops the spokes crossing each other. Each ring is then
    given whatever radius it needs to hold its own contents without crowding,
    so a wide hop pushes outward instead of overlapping.
    """
    by_level = {}
    for node in nodes:
        by_level.setdefault(node["level"], []).append(node["id"])

    below = {}
    for parent, child in down_edges:
        below.setdefault(parent, []).append(child)

    target_set = set(targets)
    is_app = {n["id"]: n["isApp"] for n in nodes}
    angle, position, rings = {}, {}, []
    previous_radius = 0.0
    arc_per_node, ring_gap, band_gap = 62.0, 190.0, 58.0

    for level in sorted(by_level):
        members = sorted(by_level[level])
        count = len(members)

        if level == min(by_level):
            if count == 1:
                position[members[0]] = (0.0, 0.0)
                angle[members[0]] = 0.0
            else:
                radius = max(30.0, count * 20.0 / (2 * math.pi))
                for i, node_id in enumerate(members):
                    theta = 2 * math.pi * i / count
                    angle[node_id] = theta
                    position[node_id] = (radius * math.cos(theta),
                                         radius * math.sin(theta))
                previous_radius = radius
            rings.append({"level": level, "radius": round(previous_radius, 1)})
            continue

        def anchor(node_id):
            known = [angle[n] for n in below.get(node_id, ()) if n in angle]
            if not known:
                return (9.9, node_id)
            # circular mean, so a node sitting either side of 0 rad is not split
            mean = math.atan2(sum(math.sin(a) for a in known) / len(known),
                              sum(math.cos(a) for a in known) / len(known))
            return (mean, node_id)

        ordered = sorted(members, key=anchor)
        # A hop holding one straggler does not deserve the same radial room as a
        # hop holding fifty. Giving every ring an equal gap pushes the outer edge
        # out for no reason, and since the view auto-fits, that shrinks
        # everything the reader actually cares about.
        busiest = max(len(v) for v in by_level.values())
        weight = 0.5 + 0.5 * math.sqrt(count / busiest) if busiest else 1.0
        radius = previous_radius + ring_gap * weight

        # A hop with far more members than its circumference can hold is split
        # across a few concentric bands rather than being crushed into one line.
        # Spreading the whole picture instead would not help: the view auto-fits,
        # so everything would simply be drawn smaller.
        capacity = max(int((2 * math.pi * radius) / arc_per_node), 8)
        bands = max(1, math.ceil(count / capacity))
        per_band = math.ceil(count / bands)

        for index, node_id in enumerate(ordered):
            band = index // per_band
            within = index % per_band
            in_this_band = min(per_band, count - band * per_band)
            theta = 2 * math.pi * within / max(in_this_band, 1)
            # stagger alternate bands so nodes do not line up radially
            theta += (math.pi / max(in_this_band, 1)) if band % 2 else 0.0
            angle[node_id] = theta
            r = radius + band * band_gap
            # applications ride just outside their band, so the things you
            # actually own sit on the leading edge of the blast
            if is_app.get(node_id) and node_id not in target_set:
                r += band_gap * 0.34
            position[node_id] = (r * math.cos(theta), r * math.sin(theta))

        previous_radius = radius + (bands - 1) * band_gap
        rings.append({"level": level, "radius": round(radius, 1),
                      "bands": bands})

    return position, rings


def graph_spec(G, app_roots, result, cap, layout="rings", focus="routes"):
    """A plain-data description of what to draw, so rendering can be cached.

    focus="routes" keeps only the packages that actually carry the compromise to
    one of your applications, plus the pins holding the rest back. Everything it
    drops is a package the blast reaches but which leads nowhere you own - real,
    counted in every metric, and pure noise in the picture.
    """
    targets = set(result["targets"])
    depth = result["depth"]
    visible = {n: d for n, d in depth.items() if d <= cap}

    shielded = list(result["shielded_apps"])
    shield_edges, extra = [], set()
    for app in shielded:
        for parent, child in shielded_route(result, app):
            shield_edges.append((parent, child))
            extra.add(parent)
            extra.add(child)

    pin_edges = {(p["parent"], p["child"]): p for p in result["pins"]}
    shown = set(visible) | set(shielded) | {n for n in extra if n in visible or n not in depth}
    shown = {n for n in shown if n in G}

    if focus == "routes":
        carries = set(targets) | set(shielded) | extra
        for app, chain in result["paths"].items():
            carries.update(chain)
        for pin in result["pins"]:
            carries.add(pin["parent"])
            carries.add(pin["child"])
        shown &= carries

    route_count = {}
    for edge in result["flow_edges"]:
        route_count[edge["from"]] = route_count.get(edge["from"], 0) + 1

    pins_by_app = {app: pins_for_app(result, app) for app in shielded}
    guarded = result.get("guarded_by", {})
    shield_depth = result.get("shield_depth", {})
    # One row per hop. Shielded packages sit just beyond the frontier they are
    # held back from, so a pin reads as a wall in the layer where it applies
    # rather than floating off on its own.
    deepest = max([cap] + [d for d in visible.values()]) if visible else cap

    nodes, level_of = [], {}
    for node in sorted(shown):
        hop = visible.get(node)
        is_app = node in app_roots
        is_target = node in targets
        name = node_name(G, node)
        version = node_version(G, node)

        if is_target:
            colour, size, shape = ORIGIN, 38, "diamond"
        elif hop is None:
            colour, size, shape = LATENT, (22 if is_app else 14), ("square" if is_app else "dot")
        else:
            colour = HOP[min(hop - 1, len(HOP) - 1)]
            size = 28 if is_app else 15
            shape = "square" if is_app else "dot"

        pin_notes = []
        if hop is None:
            for pin in (pins_by_app.get(node) or
                        [p for p in result["pins"] if p["id"] in guarded.get(node, [])])[:3]:
                pin_notes.append(
                    f"{pin['parent_name']} requires {pin['child_name']} at "
                    f"{pin['requirement']}, which does not admit "
                    f"{pin['needed_version']}")
            count = len(guarded.get(node, []))
            if count > 3:
                pin_notes.append(f"+{count - 3} more pin(s) on other routes")

        if is_target:
            title = f"{name}@{version}\ncompromised - simulating " \
                    f"{result['malicious_versions'].get(node, version)}"
        elif hop is None:
            title = f"{name}@{version}\nshielded by {len(guarded.get(node, []))} pin(s)"
        else:
            title = f"{name}@{version}\nhop {hop}"

        if hop is not None:
            level = hop
        else:
            level = min(shield_depth.get(node, deepest + 1), deepest + 2)
        level_of[node] = level

        nodes.append({
            "id": node,
            "label": name if (is_app or is_target) else "",
            "color": colour,
            "size": size,
            "shape": shape,
            "title": title,
            "level": level,
            "hop": hop if hop is not None else -1,
            "pkgName": name,
            "pkgVersion": version,
            "isApp": bool(is_app),
            "simVersion": result["malicious_versions"].get(node) if is_target else None,
            "directDeps": int(G.in_degree(node)) if is_target else None,
            "routes": route_count.get(node, 0),
            "pinNotes": pin_notes,
        })

    def sideways(a, b):
        """Two nodes on the same ring joined by a straight chord would cut
        across everything between them, so those arc instead. Spokes between
        rings stay straight."""
        if layout != "rings":
            return None
        if level_of.get(a) is None or level_of.get(b) is None:
            return None
        if level_of[a] - level_of[b] >= 1:
            return None
        return {"enabled": True, "type": "curvedCW", "roundness": 0.28}

    edges = []
    for edge in result["flow_edges"]:
        if edge["from"] not in shown or edge["to"] not in shown or edge["hop"] > cap:
            continue
        colour = HOP[min(max(edge["hop"], 1) - 1, len(HOP) - 1)]
        item = {
            "from": edge["from"], "to": edge["to"], "hop": edge["hop"],
            "kind": "infection", "color": colour,
            "width": 2 if edge["tree"] else 1,
            "dashes": False,
            "title": "carries the compromise" if edge["tree"] else "additional route",
        }
        curve = sideways(edge["from"], edge["to"])
        if curve:
            item["smooth"] = curve
        edges.append(item)

    for parent, child in dict.fromkeys(shield_edges):
        if parent not in shown or child not in shown:
            continue
        pin = pin_edges.get((parent, child))
        item = {
            "from": parent, "to": child, "hop": -1,
            "kind": "blocked" if pin else "shield",
            "color": LATENT, "width": 2 if pin else 1, "dashes": True,
            "title": (f"pinned to {pin['requirement']} - blocks {pin['needed_version']}"
                      if pin else "blocked route"),
        }
        curve = sideways(parent, child)
        if curve:
            item["smooth"] = curve
        edges.append(item)

    rings = []
    if layout == "rings" and nodes:
        down = [(e["from"], e["to"]) for e in edges
                if level_of.get(e["from"], 0) > level_of.get(e["to"], 0)]
        position, rings = _ring_layout(nodes, down, targets)
        for node in nodes:
            x, y = position.get(node["id"], (0.0, 0.0))
            node["x"], node["y"] = round(x, 1), round(y, 1)
            node["fixed"] = {"x": True, "y": True}

    # Every node's own route back to ground zero, so clicking one can light up
    # exactly how the compromise would arrive and fade everything it did not use.
    came_from = result.get("infected_from", {})
    routes = {}
    shown_ids = {n["id"] for n in nodes}
    for node in nodes:
        node_id = node["id"]
        if node_id in targets or node_id not in depth:
            continue
        chain, cursor, guard = [], node_id, 0
        while cursor is not None and guard < 64:
            if cursor not in shown_ids:
                break
            chain.append(cursor)
            if cursor in targets:
                break
            cursor = came_from.get(cursor)
            guard += 1
        if len(chain) > 1 and chain[-1] in targets:
            routes[node_id] = chain

    return {
        "nodes": nodes,
        "edges": edges,
        "targets": sorted(targets),
        "maxHop": min(result["max_hops"], cap),
        "layout": layout,
        "focus": focus,
        "hidden_count": max(0, len(set(visible) | set(shielded)) - len(shown)),
        "rings": rings,
        "routes": routes,
        "origin": ORIGIN,
        "latent": LATENT,
        "hops": HOP,
    }


def _layout_options(layout, node_count):
    """Layered reads as a blast front advancing hop by hop; organic reads as a
    neighbourhood. Both are the same data, so the choice is presentation only."""
    shared = {
        "nodes": {"font": {"color": INK, "size": 12, "face": "Source Sans Pro"},
                  "borderWidth": 1},
        "interaction": {"hover": True, "dragNodes": True, "tooltipDelay": 120,
                        "navigationButtons": False, "keyboard": False},
    }
    if layout == "organic":
        shared.update({
            "physics": {"enabled": True, "solver": "barnesHut",
                        "barnesHut": {"gravitationalConstant": -9000,
                                      "springLength": 120, "springConstant": 0.03,
                                      "avoidOverlap": 0.15},
                        "stabilization": {"iterations": 220}},
            "edges": {"smooth": {"enabled": True, "type": "continuous",
                                 "roundness": 0.2},
                      "arrows": {"to": {"enabled": True, "scaleFactor": 0.45}}},
        })
        return shared

    # Rings: every position is computed in Python, so the physics engine has
    # nothing to do and the layout is identical every time it is drawn.
    shared.update({
        "physics": {"enabled": False},
        "edges": {"smooth": {"enabled": True, "type": "continuous",
                             "roundness": 0.12},
                  "arrows": {"to": {"enabled": True, "scaleFactor": 0.4}}},
    })
    return shared


@st.cache_data(show_spinner=False, max_entries=24)
def render_graph_html(spec_json):
    spec = json.loads(spec_json)
    net = Network(height="780px", width="100%", directed=True, bgcolor=CANVAS,
                  font_color=INK, cdn_resources="in_line")
    net.set_options(json.dumps(
        _layout_options(spec.get("layout", "layered"), len(spec["nodes"])),
        separators=(",", ":")))
    for node in spec["nodes"]:
        net.add_node(node["id"], **{k: v for k, v in node.items() if k != "id"})
    for edge in spec["edges"]:
        net.add_edge(edge["from"], edge["to"],
                     **{k: v for k, v in edge.items() if k not in ("from", "to")})
    return build_animated_html(net, {
        "targets": spec["targets"], "maxHop": spec["maxHop"],
        "origin": spec["origin"], "latent": spec["latent"], "hops": spec["hops"],
        "layout": spec.get("layout", "rings"),
        "rings": spec.get("rings", []),
        "routes": spec.get("routes", {}),
        "panel": 780,
    })


# ---------------------------------------------------------------------------
# small helpers
# ---------------------------------------------------------------------------

def label_of(G, node):
    return f"{node_name(G, node)}@{node_version(G, node)}"


def names_list(G, nodes, limit=6):
    shown = [node_name(G, n) for n in nodes[:limit]]
    extra = len(nodes) - len(shown)
    return ", ".join(shown) + (f", +{extra} more" if extra > 0 else "")


def swatch(colour, text):
    return (f'<span style="display:inline-flex;align-items:center;gap:6px;'
            f'margin-right:16px;"><span style="width:11px;height:11px;border-radius:50%;'
            f'background:{colour};display:inline-block;"></span>{text}</span>')


# ---------------------------------------------------------------------------
# sidebar: which corpus, and the honesty notes
# ---------------------------------------------------------------------------

with st.sidebar:
    st.subheader("Corpus")
    source = st.radio(
        "What are we analysing?",
        ["Bundled portfolio", "Your own SBOM"],
        label_visibility="collapsed",
        help="Blast radius is only meaningful relative to a defined set of "
             "applications. In production that set is your own repositories.")

    uploaded = None
    if source == "Your own SBOM":
        uploaded = st.file_uploader(
            "CycloneDX or SPDX JSON", type=["json"], accept_multiple_files=True,
            help="One file per application. Export with `npm sbom --sbom-format "
                 "cyclonedx` or `syft`.")

corpus = None
if source == "Your own SBOM" and uploaded:
    payloads = tuple(sorted((f.name, f.getvalue()) for f in uploaded))
    corpus = load_sbom_corpus(payloads)
    if corpus is None:
        st.sidebar.error("None of those files could be read as CycloneDX or SPDX JSON.")
elif source == "Your own SBOM":
    st.sidebar.info("Upload at least one SBOM to analyse it.")

if corpus is None:
    corpus = load_bundled_corpus()

if corpus is not None and corpus.get("error"):
    st.title("💥 Blast radius")
    st.error(f"The dependency graph could not be loaded.\n\n{corpus['error']}")
    st.stop()

if corpus is None:
    st.title("💥 Blast radius")
    st.error("No graph found. Run `python fetch.py`, then `python build.py`, then "
             "restart this app.")
    st.stop()

G = corpus["G"]
app_roots = corpus["app_roots"]
rankings = corpus["rankings"]
enrichment = load_enrichment()

with st.sidebar:
    st.caption(f"**{corpus['label']}** · {len(app_roots)} applications · "
               f"{G.number_of_nodes():,} package-versions · "
               f"{G.number_of_edges():,} dependency edges")
    for note in corpus["notes"]:
        st.caption(f"· {note}")
    if not corpus["ranges"]:
        st.warning("This SBOM carries no declared version ranges, so propagation "
                   "cannot be gated. Only the lockfile-resident scenario is "
                   "meaningful here.")
    st.divider()
    st.caption(
        "**SDG 9 — Industry, Innovation and Infrastructure.** Open-source "
        "dependencies are the substrate every digital service is built on. This "
        "measures how fragile that substrate is, and which single repair buys "
        "back the most resilience.")
    st.divider()
    st.caption("**Same engine, no interface:**\n\n"
               "`python gate.py --package ms --max-exposure 10`\n\n"
               "fails a CI build when a dependency's blast radius crosses your policy.")
    if enrichment:
        st.caption(f"Advisory + maintainer data from {enrichment.get('generated', '?')}")


# ---------------------------------------------------------------------------
# header
# ---------------------------------------------------------------------------

st.title("💥 Blast radius")
st.caption("Which single package compromise costs you the most, and which upgrade "
           "buys back the most.")
st.markdown(
    "A package's own vulnerability score only measures the package. It says nothing "
    "about **how much of your portfolio sits downstream of it** — and that structural "
    "exposure is usually the bigger number. This maps the dependency graph itself to "
    "find out.")

with st.expander("How this simulation works — and what it deliberately does not claim"):
    st.markdown(f"""
A compromise starts at one package version and spreads **upward**, into things that
depend on it. Whether it crosses a dependency edge is decided by the declared version
range on that edge and the version the parent would have to accept.

**Two scenarios, and the difference matters:**

| | What it models | What pins do |
|---|---|---|
| **Already in your tree** | The malicious code *is* the version your lockfile resolved. | Nothing. It is already installed everywhere downstream. |
| **Next release** | The attacker publishes a *new* version. | A dependent only takes it if its range admits it — and a dependent that does take it must publish its own release before *its* dependents are affected. So the range check applies at **every** hop. |

- **Hop** — dependency edges between a package and the compromised one.
- **Exact pin** — one complete version (`4.2.0`). A bare `4` means `4.x.x` and is a
  *range*, not a pin.
- **Shielded** — an application whose every route in is currently blocked by a pin.
  Lagged, not safe: the *Fragile pins* tab measures exactly what happens when one moves.
- **Fix these first** — each candidate upgrade is applied to the graph and the
  propagation is **re-run**. The number shown is the measured drop in exposed
  applications, not an assumption that cutting one route saves an application that
  had two.

**What this does not claim.** Reachability is not exploitability: this models whether
malicious code reaches a build, not whether a vulnerable function is ever called.
Call-graph reachability is the honest next phase. The corpus is stated on screen rather
than implied to be the whole ecosystem.

Loaded: **{len(app_roots)} applications**, **{G.number_of_nodes() - len(app_roots):,}
packages**, **{G.number_of_edges():,} dependency edges**.
""")


# ---------------------------------------------------------------------------
# ecosystem risk map
# ---------------------------------------------------------------------------

scope_label = st.segmented_control(
    "Compromise scope",
    ["Whole package (maintainer takeover)", "One exact version"],
    default="Whole package (maintainer takeover)",
    key="scope_pick",
    help="An attacker who takes over a maintainer account can publish to every live "
         "release line at once, so the package as a whole is the realistic unit. "
         "Switch to a single version for a precise, narrower question.")
scope = SCOPE_NAME if (scope_label or "").startswith("Whole") else SCOPE_VERSION
ranked = rankings.get(scope) or []

if ranked:
    st.subheader("🗺️ Ecosystem risk map")
    st.caption("The system's own read on structural criticality, before you pick "
               "anything. Ranked on the next-release scenario.")

    left_map, right_map = st.columns([3, 2])

    with left_map:
        top = ranked[:12]
        chart = pd.DataFrame({
            "package": [row["name"] for row in top],
            "Exposed if it ships a malicious release": [row["apps"] for row in top],
            "Held back by pins": [row["held_back"] for row in top],
        }).set_index("package")
        st.bar_chart(chart, height=260, stack=True,
                     color=["#F26A4B", "#4F6B8A"])
        st.caption("Applications reached, out of "
                   f"{len(app_roots)}. The darker band is exposure that version pins "
                   "are currently delaying, not preventing.")

    with right_map:
        union = set()
        for row in ranked[:5]:
            probe = detonate(G, app_roots, row["ids"],
                             {i: bump_patch(node_version(G, i)) for i in row["ids"]},
                             detail=False)
            if probe:
                union |= set(probe["affected_apps"])
        concentration = round(100 * len(union) / max(len(app_roots), 1), 1)
        st.metric("Concentration in the top 5", f"{concentration}%",
                  help="Union of applications reachable from the 5 most structurally "
                       "critical packages — not a sum, so applications shared between "
                       "them are not double-counted.")
        st.caption(f"Compromise any **one** of the top 5 and you could reach "
                   f"**{len(union)} of {len(app_roots)}** applications. That is how "
                   f"concentrated the risk is in this graph.")

        held = sum(row["held_back"] for row in ranked[:12])
        st.metric("Application-exposures pins are delaying", held,
                  help="Across the top 12 packages, how many application exposures "
                       "are currently held back by a version pin rather than "
                       "prevented.")

    hidden = []
    for row in ranked[:40]:
        direct = max(row["direct_dependents"], 1)
        hidden.append({
            "Package": row["name"],
            "Direct dependents": row["direct_dependents"],
            "Applications reached": row["apps"],
            "Held back by pins": row["held_back"],
            "Amplification": round(row["apps"] / direct, 2),
        })
    hidden.sort(key=lambda r: -r["Amplification"])
    st.markdown("**Packages more dangerous than they look** — few packages depend on "
                "these *directly*, but the ripple still reaches far more applications "
                "than that number suggests:")
    st.dataframe(hidden[:8], width="stretch", hide_index=True)

    # --- what the graph knows that a CVE feed does not ----------------------
    if enrichment:
        vuln_nodes = enrichment.get("vulns_by_node") or {}
        maintainers = enrichment.get("maintainers") or {}
        col_v, col_m = st.columns(2)

        with col_v:
            st.markdown("**Known advisories on these packages**")
            covered = [row for row in ranked[:40] if any(
                node in vuln_nodes for node in row["ids"])]
            if covered:
                rows = []
                for row in covered[:8]:
                    ids = [v for node in row["ids"] for v in vuln_nodes.get(node, [])]
                    details = enrichment.get("vuln_details") or {}
                    worst = max((details.get(v, {}).get("score") or 0) for v in ids)
                    rows.append({"Package": row["name"],
                                 "Advisories": len(set(ids)),
                                 "Worst CVSS": worst or "—",
                                 "Applications reached": row["apps"]})
                st.dataframe(rows, width="stretch", hide_index=True)
            else:
                st.info(
                    "**Zero known advisories** affect the resolved versions of the "
                    "40 most structurally critical packages in this corpus "
                    "(checked against OSV.dev).\n\n"
                    "That is not a clean bill of health — it is the argument. A "
                    "vulnerability scanner would report nothing here, while the "
                    f"graph shows a single compromise reaching {ranked[0]['apps']} of "
                    f"{len(app_roots)} applications. Structural risk exists whether or "
                    "not anyone has filed a CVE yet.")

        with col_m:
            st.markdown("**Who can publish to them**")
            if maintainers:
                rows = []
                for row in ranked[:40]:
                    count = maintainers.get(row["name"])
                    if count is None:
                        continue
                    rows.append({"Package": row["name"], "Maintainers": count,
                                 "Applications reached": row["apps"]})
                solo = [r for r in rows if r["Maintainers"] <= 1]
                if solo:
                    solo.sort(key=lambda r: -r["Applications reached"])
                    st.dataframe(solo[:8], width="stretch", hide_index=True)
                    st.caption(
                        f"**{len(solo)} of {len(rows)}** critical packages here have a "
                        "single maintainer. Structural criticality says how far a "
                        "compromise spreads; maintainer count says how hard it is to "
                        "start one. Neither number finds this on its own.")
                else:
                    st.caption("No single-maintainer packages among the ranked set.")
            else:
                st.caption("Run `python enrich.py` to add maintainer counts.")
    else:
        st.caption("Optional: `python enrich.py` adds OSV advisories and maintainer "
                   "counts to this section.")


# ---------------------------------------------------------------------------
# picker
# ---------------------------------------------------------------------------

st.divider()
left, right = st.columns([2, 1])

with right:
    st.subheader("Pick a package to compromise")

    present = [(name, INCIDENTS[name]) for name in INCIDENTS if nodes_named(G, name)]
    if present:
        st.caption("**Real compromises, still in this corpus.** Every button below "
                   "is a package that was actually attacked or sabotaged in the "
                   "wild — and that this portfolio still depends on today:")
        cols = st.columns(min(len(present), 3))
        for i, (name, (year, story)) in enumerate(present[:6]):
            with cols[i % len(cols)]:
                if st.button(f"{name} · {year}", key=f"incident_{name}",
                             width="stretch", help=story):
                    st.session_state["preset_target"] = name

        with st.expander("What happened to each of these"):
            for name, (year, story) in present[:6]:
                reach = len(nodes_named(G, name))
                st.markdown(f"**`{name}` — {year}.** {story} "
                            f"_({reach} version(s) of it are in this corpus.)_")
            st.caption(
                "Pick one and simulate it: most reach only one or two applications "
                "here. That contrast is the point — a famous incident can be small "
                "in your portfolio while an unremarkable utility nobody has heard "
                "of sits under a third of it. Severity and fame do not predict "
                "blast radius; position in the graph does.")

    options = [row["key"] for row in ranked] if ranked else []
    if options:
        by_key = {row["key"]: row for row in ranked}
        # Switching scope (or corpus) changes the option set. A value left in
        # session state from the previous set would make the selectbox raise, so
        # it is cleared before the widget is built.
        if st.session_state.get("target_pick") not in by_key:
            st.session_state.pop("target_pick", None)
        preset = st.session_state.pop("preset_target", None)
        if preset:
            match = next((k for k in options if by_key[k]["name"] == preset), None)
            if match:
                st.session_state["target_pick"] = match
            else:
                st.session_state["free_name"] = preset

        def describe(key):
            row = by_key[key]
            return (f"{row['name']} — {row['apps']} app(s), "
                    f"{row['exposure_pct']}% exposure")

        picked_key = st.selectbox("Ranked by blast radius", options,
                                  format_func=describe, key="target_pick",
                                  label_visibility="collapsed")
        row = by_key[picked_key]
        targets = list(row["ids"]) if scope == SCOPE_NAME else [row["id"]]
    else:
        targets = []

    with st.expander("Something not in the ranking"):
        free = st.text_input("Package name", key="free_name",
                             placeholder="e.g. colors")
        if free.strip():
            found = nodes_named(G, free.strip())
            if found:
                targets = found if scope == SCOPE_NAME else [found[0]]
                st.success(f"Using {len(found)} version(s) of `{free.strip()}`.")
            else:
                st.warning(f"`{free.strip()}` is not in this corpus.")

    if not targets:
        st.info("Nothing selectable in this corpus yet.")
        st.stop()

    scenario = st.radio(
        "Scenario",
        ["Next release (attacker publishes)", "Already in your tree"],
        key="scenario_pick",
        help="Next release is the scenario version pins actually defend against, so "
             "it is the default. 'Already in your tree' shows the worst case: the "
             "malicious code is the version your lockfile resolved, and no pin helps.")
    future = scenario.startswith("Next release")

    custom = ""
    if scope == SCOPE_VERSION and future:
        with st.expander("Simulate a specific version"):
            custom = st.text_input(
                "Malicious version", key="custom_version",
                placeholder=bump_patch(node_version(G, targets[0])),
                help="Defaults to the next patch release of the installed version.")

    budget = st.slider("How many upgrades can you afford?", 1, 5, 3, key="budget_pick",
                       help="Each upgrade is applied to the graph and the propagation "
                            "is re-run, so the reduction shown is measured.")
    go = st.button("Simulate compromise", type="primary", width="stretch")

# The inputs are frozen at the moment of the click, so results survive every
# other widget on the page triggering its own rerun.
if go:
    versions = {}
    for node in targets:
        installed = node_version(G, node)
        if not future:
            versions[node] = installed
        elif custom.strip() and len(targets) == 1:
            versions[node] = custom.strip()
        else:
            versions[node] = bump_patch(installed)
    st.session_state["sim"] = {
        "corpus": corpus["id"], "targets": list(targets),
        "versions": versions, "budget": budget,
        "scope": scope, "scenario": scenario,
    }

sim = st.session_state.get("sim")
if sim and sim.get("corpus") != corpus["id"]:
    sim = None
    st.session_state.pop("sim", None)

if not sim:
    with left:
        st.info("Choose a package and press **Simulate compromise** to see how far it "
                "spreads.")
    st.stop()

result = detonate(G, app_roots, sim["targets"], sim["versions"])
if result is None:
    st.session_state.pop("sim", None)
    st.error("That package is no longer in the loaded corpus. Pick another and "
             "simulate again.")
    st.stop()

mitigation = rank_mitigations(G, app_roots, result, budget=sim["budget"])
fragility = pin_fragility(G, app_roots, result)

target_names = sorted({node_name(G, t) for t in result["targets"]})
headline = ", ".join(target_names)
direct_dependents = sum(G.in_degree(t) for t in result["targets"])
rank_position = next((i + 1 for i, row in enumerate(ranked)
                      if set(row["ids"]) & set(result["targets"])), None)

# stale-selection cue (the picker moved but Simulate has not been pressed again)
pending = set(targets) != set(sim["targets"]) or scenario != sim["scenario"] \
    or scope != sim["scope"]

with right:
    if pending:
        st.warning(f"Showing **{headline}**. Press **Simulate compromise** to run the "
                   "current selection.")

    st.subheader(f"🎯 {headline}")
    rank_note = (f"ranked **#{rank_position}** of {len(ranked)} by blast radius · "
                 if rank_position else "")
    versions_note = ", ".join(sorted(set(result["malicious_versions"].values())))
    st.caption(f"{rank_note}{direct_dependents} package(s) depend on it directly · "
               f"{len(result['targets'])} version(s) compromised · "
               f"simulating **{versions_note}** · _{result['scenario']}_")

    st.metric("Portfolio exposed", f"{result['exposure_pct']}%",
              help="Share of tracked applications a compromise here would reach.")
    a, b, c = st.columns(3)
    a.metric("Applications hit", len(result["affected_apps"]),
             help="Reached with no pin in the way.")
    b.metric("Shielded by pins", len(result["shielded_apps"]),
             help="Every route in is currently blocked by a version pin. Lagged, "
                  "not safe.")
    c.metric("Max hops", result["max_hops"],
             help="Longest chain of dependencies the compromise crossed.")
    st.metric("Package-versions reached", len(result["reached"]))

    verdict = (f"**{headline}** sits behind **{len(result['reached'])} package-version(s)**. "
               f"A compromise there reaches **{len(result['affected_apps'])} of "
               f"{len(app_roots)} applications** ({result['exposure_pct']}%) within "
               f"**{result['max_hops']} hop(s)**")
    verdict += (f", plus **{len(result['shielded_apps'])} more** held back only by a "
                "version pin." if result["shielded_apps"] else ".")
    st.markdown(verdict)

    st.subheader("Fix these first")
    if mitigation["fixes"]:
        for i, fix in enumerate(mitigation["fixes"], 1):
            with st.container(border=True):
                st.markdown(f"**{i}. Upgrade `{fix['name']}@{fix['version']}`** — "
                            f"removes exposure for {fix['apps_saved']} application(s)")
                st.caption(names_list(G, fix["apps_covered"]))
        st.success(f"{mitigation['apps_before']} applications exposed → "
                   f"{mitigation['apps_after']} after {len(mitigation['fixes'])} "
                   f"upgrade(s) ({mitigation['reduction_pct']}% reduction)")
        st.caption("Verified: the propagation was re-run with each package patched. "
                   "This is a measured difference between two simulations.")
    else:
        st.info("No upstream upgrade measurably reduces exposure here — every exposed "
                "application depends on the compromised package directly, or the "
                "alternative routes make a single upgrade worthless.")

    if mitigation["direct_apps"]:
        st.warning(f"{len(mitigation['direct_apps'])} application(s) depend on "
                   f"**{headline}** directly, so no upstream upgrade helps them — they "
                   f"need a direct patch: {names_list(G, mitigation['direct_apps'])}")

    st.download_button(
        "⬇ Download incident brief (Markdown)",
        data=incident_brief(G, app_roots, result, mitigation, fragility,
                            corpus=corpus["label"]),
        file_name=f"blast-radius-{target_names[0].replace('/', '-')}.md",
        mime="text/markdown", width="stretch",
        help="A one-page brief for whoever has to make the upgrade — they are usually "
             "not the person who ran the scan.")


# ---------------------------------------------------------------------------
# the graph
# ---------------------------------------------------------------------------

with left:
    st.subheader("Watch it spread")

    legend = "".join([
        swatch(ORIGIN, "compromised"),
        swatch(HOP[0], "hop 1"), swatch(HOP[1], "hop 2"),
        swatch(HOP[2], "hop 3"), swatch(HOP[3], "hop 4+"),
        swatch(LATENT, "shielded by a pin"),
    ])
    st.markdown(f'<div style="font-size:0.82rem;margin-bottom:2px;">{legend}</div>',
                unsafe_allow_html=True)
    st.caption("◆ diamond = the compromised package · ■ square = an application · "
               "● dot = an intermediate package · **click any node for its version, "
               "status and why**.")

    ctl_left, ctl_mid, ctl_right = st.columns([2, 2, 2])
    with ctl_left:
        cap = st.slider("Depth to include", 0, max(result["max_hops"], 1),
                        max(result["max_hops"], 1), key="depth_cap",
                        help="Caps how many hops the graph and animation cover — "
                             "lower it to declutter a very wide blast.")
    with ctl_mid:
        layout_label = st.radio(
            "Layout", ["Blast rings", "Organic"], key="layout_pick",
            horizontal=True,
            help="Blast rings put the compromised package at ground zero, with one "
                 "ring per hop outward — distance from the centre is distance from "
                 "the compromise. Organic is a force-directed view that shows "
                 "clustering instead.")
    with ctl_right:
        focus_label = st.radio(
            "Show", ["Routes that reach you", "Every package"], key="focus_pick",
            horizontal=True,
            help="The blast reaches plenty of packages that lead nowhere you own. "
                 "They are real and they are counted in every metric on this page, "
                 "but they add nothing to the picture. 'Routes that reach you' "
                 "draws only the packages that actually carry the compromise to one "
                 "of your applications, plus the pins holding the rest back.")
    layout = "organic" if layout_label == "Organic" else "rings"
    focus = "all" if focus_label == "Every package" else "routes"

    spec = graph_spec(G, app_roots, result, cap, layout=layout, focus=focus)
    components.html(render_graph_html(json.dumps(spec, sort_keys=True)),
                    height=852, scrolling=False)

    if layout == "rings":
        st.caption("**Ground zero is the centre.** Each ring out is one more hop, "
                   "and your applications ride on the outer edge of their ring. "
                   "**Click any node** to light up its exact route back to the "
                   "centre and fade everything the compromise never touched.")
    if spec["hidden_count"] > 0:
        st.caption(f"Drawing {len(spec['nodes'])} of "
                   f"{len(spec['nodes']) + spec['hidden_count']} reached "
                   f"package-versions — the other {spec['hidden_count']} are carrying "
                   f"the compromise but lead nowhere you own. They stay in every "
                   f"number on this page; switch **Show** to *Every package* to draw "
                   f"them too.")

    extra_routes = len(spec["edges"]) and sum(
        1 for e in spec["edges"] if e["kind"] == "infection" and e["width"] == 1)
    st.caption(
        "Arrows follow the dependency graph (dependent → dependency); the compromise "
        "travels the other way — watch the pulses climb outward from the origin. "
        f"**Every admitting route is drawn, not just one per package** — {extra_routes} "
        "of the solid edges here are redundant routes, which is exactly why cutting a "
        "single link often saves nobody. Dashed blue edges are routes a version pin is "
        "currently blocking.")


# ---------------------------------------------------------------------------
# the detail
# ---------------------------------------------------------------------------

st.divider()
st.subheader("How it reaches each application")

tab_hit, tab_shielded, tab_pins, tab_trace = st.tabs([
    f"Exposed ({len(result['affected_apps'])})",
    f"Shielded ({len(result['shielded_apps'])})",
    f"Fragile pins ({len(fragility)})",
    "Reasoning trace",
])

with tab_hit:
    if result["affected_apps"]:
        rows = []
        for app in result["affected_apps"]:
            chain = [node_name(G, x) for x in result["paths"][app]]
            routes = sum(1 for e in result["flow_edges"] if e["from"] == app)
            rows.append({
                "Application": node_name(G, app),
                "Hops": result["depth"][app],
                "Routes in": routes,
                "Shortest route": " ← ".join(chain),
            })
        rows.sort(key=lambda r: (r["Hops"], -r["Routes in"]))
        st.dataframe(rows, width="stretch", hide_index=True)
        st.caption("'Routes in' counts the distinct admitting dependency edges that "
                   "reach this application. Anything above 1 means a single upgrade "
                   "upstream will not save it.")
    else:
        st.write("No application is exposed in this scenario.")

with tab_shielded:
    if result["shielded_apps"]:
        rows = []
        for app in result["shielded_apps"]:
            pins = pins_for_app(result, app)
            first = pins[0] if pins else None
            rows.append({
                "Application": node_name(G, app),
                "Pins holding": len(pins),
                "Nearest pin": (f"{first['parent_name']} requires "
                                f"{first['child_name']} at {first['requirement']}"
                                if first else "—"),
                "Which will not take": first["needed_version"] if first else "—",
            })
        rows.sort(key=lambda r: r["Pins holding"])
        st.dataframe(rows, width="stretch", hide_index=True)
        st.caption(
            "Shielding is transitive: an application counts as shielded when **every** "
            "route in is blocked, even when the pin doing the blocking sits several "
            "hops away rather than on the application itself.")
    elif result["republish"]:
        st.write("No application is shielded — every reachable application is exposed.")
    else:
        st.info("In the **already in your tree** scenario nothing can be shielded: the "
                "malicious version is the one your lockfile already resolved, so no "
                "range has to admit anything. Switch to **Next release** to see which "
                "pins would hold a future compromise back.")

with tab_pins:
    if fragility:
        st.markdown("**Pinned is lagged, not safe.** Each row below widens exactly one "
                    "range and re-runs the propagation, so the cost of that pin moving "
                    "is measured rather than assumed:")
        rows = []
        for entry in fragility:
            pin = entry["pin"]
            rows.append({
                "If this pin moves": f"{label_of(G, pin['parent'])} → "
                                     f"{label_of(G, pin['child'])}",
                "Currently requires": pin["requirement"],
                "Blocking": pin["needed_version"],
                "Exact pin": "yes" if pin["exact_pin"] else "no (range)",
                "Newly exposed": entry["count"],
                "Which applications": names_list(G, entry["newly_exposed"], 4) or "—",
            })
        st.dataframe(rows, width="stretch", hide_index=True)
        worst = fragility[0]
        if worst["count"]:
            st.caption(
                f"The most load-bearing pin here is "
                f"`{worst['pin']['parent_name']}` requiring "
                f"`{worst['pin']['requirement']}`. One bump to that single line exposes "
                f"{worst['count']} more application(s) — no attacker action required.")
    else:
        st.write("No pin is currently holding anything back in this scenario.")

with tab_trace:
    if result["affected_apps"]:
        st.markdown("**The exact semver check at each hop** — the same test the "
                    "propagation made while walking the graph, surfaced so the 'why' "
                    "is not just asserted:")
        traced = st.selectbox(
            "Explain how the compromise reaches...",
            options=result["affected_apps"],
            format_func=lambda a: node_name(G, a),
            label_visibility="collapsed", key="trace_pick")
        for step in explain_path(G, result["paths"][traced], result):
            if step["origin"]:
                why = ("the compromised release itself" if result["republish"]
                       else "the version already resolved in the tree")
            else:
                why = ("the release it must cut to pass the compromise on"
                       if result["republish"] else "its installed version")
            pin_flag = (" — an **exact pin**, which only admitted this because the "
                        "version matches it exactly" if step["exact_pin"] else "")
            st.markdown(
                f"**Hop {step['hop']}:** `{step['parent_name']}` requires "
                f"`{step['child_name']}` at `{step['requirement']}`, which admits "
                f"`{step['version']}` ({why}){pin_flag} → propagates.")
        st.caption("Every hop above was gated. In the next-release scenario a package "
                   "only passes the compromise on by publishing, and that published "
                   "version is what the next range up has to accept.")
    else:
        st.write("Nothing propagated, so there is no route to explain.")

st.divider()
st.caption(
    f"Corpus: **{corpus['label']}** — {len(app_roots)} applications, "
    f"{G.number_of_nodes():,} package-versions, {G.number_of_edges():,} edges. "
    "Every figure on this page is a count produced by the simulation; none of them is "
    "a weighted score with invented coefficients. Reachability is not exploitability.")
