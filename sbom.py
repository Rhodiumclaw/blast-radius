"""
Point the analysis at your own software instead of the bundled corpus.

Accepts CycloneDX or SPDX JSON and converts it into the same record shape
fetch.py produces, so every other part of the tool works unchanged.

    python sbom.py bom.json                 # inspect what would be imported
    python sbom.py bom.json --out records.json --append

A caveat worth stating out loud: a BOM describes a *resolved* tree and usually
carries no declared version ranges. Without ranges there is nothing to gate on,
so an imported SBOM is analysed in the lockfile-resident scenario only - every
edge is treated as admitting. Where a BOM does carry ranges (CycloneDX
`properties` or a `vers:` range in the purl qualifier) they are used.
"""
from __future__ import annotations

import argparse
import json
import os
import sys


class SbomError(ValueError):
    """The file is not a BOM we can read."""


def _clean(value, fallback):
    if not isinstance(value, str):
        value = "" if value is None else str(value)
    return value.strip() or fallback


def _as_list(value):
    """A BOM in the wild is not always well-formed. Anything that should be a
    list but is not is treated as absent rather than raising halfway through."""
    return value if isinstance(value, list) else []


def _as_dict(value):
    return value if isinstance(value, dict) else {}


def _purl_range(purl):
    """CycloneDX sometimes carries the declared range as a purl qualifier."""
    if not isinstance(purl, str) or "?" not in purl:
        return None
    query = purl.split("?", 1)[1]
    for part in query.split("&"):
        if part.startswith("vers="):
            return part[len("vers="):] or None
    return None


def _component_id(name, version):
    return f"npm:{name}@{version}"


def parse_cyclonedx(doc):
    metadata = _as_dict(doc.get("metadata"))
    root_component = _as_dict(metadata.get("component"))

    by_ref, components = {}, []

    def add(component):
        component = _as_dict(component)
        name = _clean(component.get("name"), None)
        if not name:
            return None
        version = _clean(component.get("version"), "0.0.0")
        node = {"id": _component_id(name, version), "name": name, "version": version}
        ref = component.get("bom-ref") or component.get("purl") or node["id"]
        if ref in by_ref:
            return by_ref[ref]
        by_ref[ref] = node
        node["_ref"] = ref
        node["_purl"] = component.get("purl")
        components.append(node)
        return node

    root = add(root_component) if root_component.get("name") else None
    for component in _as_list(doc.get("components")):
        add(component)
        for nested in _as_list(_as_dict(component).get("components")):
            add(nested)

    if not components:
        raise SbomError("CycloneDX document contains no components")

    if root is None:
        root = components[0]

    # root first: build_graph treats records[0] as the application
    ordered = [root] + [c for c in components if c["_ref"] != root["_ref"]]
    index = {c["_ref"]: i for i, c in enumerate(ordered)}

    edges = []
    for dependency in _as_list(doc.get("dependencies")):
        dependency = _as_dict(dependency)
        src = index.get(dependency.get("ref"))
        if src is None:
            continue
        for target_ref in _as_list(dependency.get("dependsOn")):
            dst = index.get(target_ref)
            if dst is None or dst == src:
                continue
            edges.append({"from": src, "to": dst,
                          "requirement": _purl_range(ordered[dst].get("_purl")) or "*"})

    nodes = [{"id": c["id"], "name": c["name"], "version": c["version"]} for c in ordered]
    return {"root": nodes[0]["id"], "nodes": nodes, "edges": edges}


def parse_spdx(doc):
    packages = _as_list(doc.get("packages"))
    if not packages:
        raise SbomError("SPDX document contains no packages")

    nodes, index = [], {}
    for package in packages:
        package = _as_dict(package)
        name = _clean(package.get("name"), None)
        if not name:
            continue
        version = _clean(package.get("versionInfo"), "0.0.0")
        spdx_id = package.get("SPDXID") or _component_id(name, version)
        if spdx_id in index:
            continue
        index[spdx_id] = len(nodes)
        nodes.append({"id": _component_id(name, version), "name": name, "version": version})

    if not nodes:
        raise SbomError("SPDX document contains no usable packages")

    describes = [r for r in _as_list(doc.get("documentDescribes")) if r in index]
    root_id = describes[0] if describes else None

    edges = []
    for relationship in _as_list(doc.get("relationships")):
        relationship = _as_dict(relationship)
        kind = _clean(relationship.get("relationshipType"), "").upper()
        src_id = relationship.get("spdxElementId")
        dst_id = relationship.get("relatedSpdxElement")
        if kind == "DESCRIBES" and root_id is None and dst_id in index:
            root_id = dst_id
        if kind not in ("DEPENDS_ON", "CONTAINS", "DEPENDENCY_OF"):
            continue
        if kind == "DEPENDENCY_OF":
            src_id, dst_id = dst_id, src_id
        src, dst = index.get(src_id), index.get(dst_id)
        if src is None or dst is None or src == dst:
            continue
        edges.append({"from": src, "to": dst, "requirement": "*"})

    root = index.get(root_id, 0)
    if root != 0:  # make the described package the record root
        order = [root] + [i for i in range(len(nodes)) if i != root]
        remap = {old: new for new, old in enumerate(order)}
        nodes = [nodes[i] for i in order]
        edges = [{"from": remap[e["from"]], "to": remap[e["to"]],
                  "requirement": e["requirement"]} for e in edges]

    return {"root": nodes[0]["id"], "nodes": nodes, "edges": edges}


def parse_sbom(doc):
    """Detect the format and return one record, plus what we learned about it."""
    if not isinstance(doc, dict):
        raise SbomError("expected a JSON object at the top level")

    if doc.get("bomFormat") == "CycloneDX" or "components" in doc:
        record = parse_cyclonedx(doc)
        fmt = f"CycloneDX {doc.get('specVersion', '')}".strip()
    elif doc.get("spdxVersion") or "packages" in doc:
        record = parse_spdx(doc)
        fmt = doc.get("spdxVersion") or "SPDX"
    else:
        raise SbomError("not recognisable as CycloneDX or SPDX JSON")

    declared = sum(1 for e in record["edges"] if e["requirement"] != "*")
    return record, {
        "format": fmt,
        "components": len(record["nodes"]),
        "dependencies": len(record["edges"]),
        "declared_ranges": declared,
        "root": record["root"],
    }


def load_sbom(raw):
    """Parse SBOM bytes or text. Raises SbomError with a readable message."""
    if isinstance(raw, (bytes, bytearray)):
        try:
            raw = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise SbomError("file is not UTF-8 text") from exc
    try:
        doc = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise SbomError(f"not valid JSON: {exc.msg} (line {exc.lineno})") from exc
    return parse_sbom(doc)


def main():
    parser = argparse.ArgumentParser(description="Import a CycloneDX or SPDX SBOM.")
    parser.add_argument("path", help="path to the SBOM JSON file")
    parser.add_argument("--out", default=None,
                        help="write the record to this records file")
    parser.add_argument("--append", action="store_true",
                        help="add to the existing records file instead of replacing it")
    args = parser.parse_args()

    if not os.path.exists(args.path):
        print(f"ERROR: {args.path} not found")
        sys.exit(1)

    with open(args.path, "r", encoding="utf-8") as f:
        raw = f.read()

    try:
        record, info = load_sbom(raw)
    except SbomError as exc:
        print(f"ERROR: {exc}")
        sys.exit(1)

    print(f"Format            : {info['format']}")
    print(f"Application       : {info['root']}")
    print(f"Components        : {info['components']:,}")
    print(f"Dependency edges  : {info['dependencies']:,}")
    print(f"Declared ranges   : {info['declared_ranges']:,}")
    if not info["declared_ranges"]:
        print("\nNo declared version ranges in this BOM, so propagation cannot be "
              "gated:\nit will be analysed in the lockfile-resident scenario only.")

    if not args.out:
        print("\n(nothing written - pass --out records.json to import)")
        return

    records = []
    if args.append and os.path.exists(args.out):
        with open(args.out, "r", encoding="utf-8") as f:
            records = json.load(f)
        records = [r for r in records if r.get("root") != record["root"]]
    records.append(record)

    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(records, f)
    print(f"\nWrote {len(records)} application(s) to {args.out}")
    print("Next: python build.py")


if __name__ == "__main__":
    main()
