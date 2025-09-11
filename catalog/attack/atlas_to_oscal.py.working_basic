#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
atlas_to_oscal.py
Convert MITRE ATLAS techniques & mitigations to an OSCAL Catalog (JSON).

Default source: ATLAS STIX 2.1 bundle (follows ATT&CK data model)
 - techniques      -> attack-pattern SDOs
 - mitigations     -> course-of-action SDOs
 - relationships   -> mitigates/subtechnique-of
MITRE ATLAS data:
  - STIX/Navigator outputs: https://github.com/mitre-atlas/atlas-navigator-data (dist/stix-atlas.json)
  - Unified YAML:          https://github.com/mitre-atlas/atlas-data (dist/ATLAS.yaml)

OSCAL reference (catalog JSON):
  - https://pages.nist.gov/OSCAL-Reference/models/v1.1.3/catalog/json-reference/

Usage examples:
  # STIX (default), remote:
  python atlas_to_oscal.py --out atlas-oscal-catalog.json
  # STIX from local file:
  python atlas_to_oscal.py --input ./stix-atlas.json --out atlas-oscal-catalog.json

  # YAML (needs PyYAML):
  python atlas_to_oscal.py --source yaml --out atlas-oscal-catalog.json
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import sys
import uuid
import urllib.request

try:
    import yaml  # Optional, only needed for --source yaml
except Exception:
    yaml = None


DEFAULT_STIX_URL = (
    "https://raw.githubusercontent.com/mitre-atlas/atlas-navigator-data/main/dist/stix-atlas.json"
)
DEFAULT_YAML_URL = (
    "https://raw.githubusercontent.com/mitre-atlas/atlas-data/main/dist/ATLAS.yaml"
)


def fetch_bytes(path_or_url: str) -> bytes:
    if re.match(r"^https?://", path_or_url, flags=re.I):
        with urllib.request.urlopen(path_or_url) as r:
            return r.read()
    with open(path_or_url, "rb") as f:
        return f.read()


def safe_slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")


def get_external_id(stix_obj: dict) -> str | None:
    """Return first external_id if present (e.g., T#### style)."""
    for ref in stix_obj.get("external_references", []):
        if "external_id" in ref:
            return ref["external_id"]
    return None


def get_first_url(stix_obj: dict) -> str | None:
    for ref in stix_obj.get("external_references", []):
        if "url" in ref:
            return ref["url"]
    return None


def parse_stix_bundle(stix_bytes: bytes, source_url: str | None = None) -> dict:
    """Parse ATLAS STIX 2.1 bundle and build intermediate structures."""
    bundle = json.loads(stix_bytes.decode("utf-8"))
    objs = bundle.get("objects", [])

    tactics_by_id = {}
    tactic_by_shortname = {}
    techniques = {}
    mitigations = {}
    relationships = []

    for o in objs:
        t = o.get("type")
        if t == "x-mitre-tactic":
            shortname = (
                o.get("x_mitre_shortname")
                or o.get("x_mitre_short_name")
                or safe_slug(o.get("name", "tactic"))
            )
            tactics_by_id[o["id"]] = {**o, "shortname": shortname}
            tactic_by_shortname[shortname] = {**o, "shortname": shortname}
        elif t == "attack-pattern":
            if o.get("x_mitre_deprecated") or o.get("revoked"):
                continue
            techniques[o["id"]] = o
        elif t == "course-of-action":
            if o.get("x_mitre_deprecated") or o.get("revoked"):
                continue
            mitigations[o["id"]] = o
        elif t == "relationship":
            relationships.append(o)

    # Technique -> [tactic shortnames]
    tech_to_tactics = {}
    for tid, tech in techniques.items():
        phases = tech.get("kill_chain_phases", [])
        tactic_shortnames = [
            p.get("phase_name")
            for p in phases
            if p.get("kill_chain_name")
        ]
        # Fallback: x_mitre_tactic_refs -> tactic IDs
        if not tactic_shortnames and tech.get("x_mitre_tactic_refs"):
            for tac_id in tech["x_mitre_tactic_refs"]:
                tac = tactics_by_id.get(tac_id)
                if tac:
                    tactic_shortnames.append(tac["shortname"])
        # Deduplicate in order
        tech_to_tactics[tid] = list(dict.fromkeys([s for s in tactic_shortnames if s]))

    # Parent technique -> [subtechniques]; technique -> set(mitigation IDs)
    parent_to_children = {}
    tech_to_mitigations = {}
    for r in relationships:
        rtype = r.get("relationship_type")
        src = r.get("source_ref")
        tgt = r.get("target_ref")
        if rtype == "subtechnique-of":
            # src=subtechnique attack-pattern, tgt=parent attack-pattern
            parent_to_children.setdefault(tgt, []).append(src)
        elif rtype == "mitigates":
            # src=course-of-action (mitigation), tgt=attack-pattern (tech)
            if tgt in techniques and src in mitigations:
                tech_to_mitigations.setdefault(tgt, set()).add(src)

    # Sort children for stability
    for k in list(parent_to_children.keys()):
        parent_to_children[k] = sorted(set(parent_to_children[k]))

    return {
        "source_url": source_url,
        "bundle": bundle,
        "tactics_by_id": tactics_by_id,
        "tactic_by_shortname": tactic_by_shortname,
        "techniques": techniques,
        "mitigations": mitigations,
        "tech_to_tactics": tech_to_tactics,
        "parent_to_children": parent_to_children,
        "tech_to_mitigations": tech_to_mitigations,
    }


def parse_yaml(atlas_yaml_bytes: bytes, source_url: str | None = None) -> dict:
    if yaml is None:
        raise RuntimeError("PyYAML is required for --source yaml. pip install pyyaml")
    data = yaml.safe_load(atlas_yaml_bytes.decode("utf-8"))
    # The YAML packs tactics/techniques/mitigations; it may not include the
    # explicit technique<->mitigation relationships like STIX does.
    # We’ll still map tactics/techniques/mitigations; mitigations linkage will be empty.
    matrices = data.get("matrices", [])
    first = matrices[0] if matrices else {}
    tactics = first.get("tactics", [])
    techniques = first.get("techniques", [])
    mitigations = data.get("mitigations", [])

    tactics_by_id = {}
    tactic_by_shortname = {}
    for t in tactics:
        sid = t.get("id") or t.get("name")
        shortname = t.get("shortname") or safe_slug(t.get("name", "tactic"))
        tactics_by_id[sid] = {**t, "id": sid, "shortname": shortname}
        tactic_by_shortname[shortname] = tactics_by_id[sid]

    # Shim to mimic STIX parse return
    tech_map = {}
    parent_to_children = {}
    tech_to_tactics = {}
    for te in techniques:
        tid = te.get("id") or te.get("name")
        tech_map[tid] = te
        if te.get("subtechnique-of"):
            parent = te["subtechnique-of"]
            parent_to_children.setdefault(parent, []).append(tid)
        # Use tactic shortnames if present
        tacts = te.get("tactics") or []
        tacts = [t if isinstance(t, str) else t.get("shortname") for t in tacts]
        tech_to_tactics[tid] = [s for s in tacts if s]

    mit_map = {m.get("id") or m.get("name"): m for m in mitigations}

    return {
        "source_url": source_url,
        "bundle": None,
        "tactics_by_id": tactics_by_id,
        "tactic_by_shortname": tactic_by_shortname,
        "techniques": tech_map,
        "mitigations": mit_map,
        "tech_to_tactics": tech_to_tactics,
        "parent_to_children": parent_to_children,
        "tech_to_mitigations": {},  # Not available in plain YAML
    }


def build_oscal_catalog(parsed: dict, oscal_version: str = "1.1.3", title: str | None = None) -> dict:
    now = dt.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
    title = title or "MITRE ATLAS Techniques & Mitigations (OSCAL Catalog)"

    catalog = {
        "catalog": {
            "uuid": str(uuid.uuid4()),
            "metadata": {
                "title": title,
                "last-modified": now,
                "version": "atlas-to-oscal-{}".format(now[:10]),
                "oscal-version": oscal_version,
                "links": [
                    {"href": "https://atlas.mitre.org", "rel": "source"},
                ]
            },
            "groups": []
        }
    }
    if parsed.get("source_url"):
        catalog["catalog"]["metadata"]["links"].append(
            {"href": parsed["source_url"], "rel": "source"}
        )

    # Tactic groups
    groups_by_short = {}
    for shortname, tac in parsed["tactic_by_shortname"].items():
        group = {
            "id": f"atlas-tactic-{safe_slug(shortname)}",
            "title": tac.get("name", shortname),
            "controls": []
        }
        groups_by_short[shortname] = group

    # Mitigations group
    mitig_group = {
        "id": "atlas-mitigations",
        "title": "ATLAS Mitigations",
        "controls": []
    }

    # Build mitigation controls
    mit_ctrl_id = {}  # stix or yaml id -> control-id
    for mid, m in parsed["mitigations"].items():
        ext_id = get_external_id(m) if isinstance(m, dict) else None
        ext_or_stix = (ext_id or str(mid).split("--")[-1]).lower()
        ctrl_id = f"atlas-mitigation-{safe_slug(ext_or_stix)}"
        mit_ctrl_id[mid] = ctrl_id
        ctrl = {
            "id": ctrl_id,
            "title": m.get("name") if isinstance(m, dict) else str(mid),
            "props": [
                {"name": "atlas:object-type", "ns": "https://atlas.mitre.org", "value": "mitigation"},
                {"name": "atlas:source-id", "ns": "https://atlas.mitre.org", "value": str(mid)},
            ],
            "links": []
        }
        url = get_first_url(m) if isinstance(m, dict) else None
        if url:
            ctrl["links"].append({"href": url, "rel": "reference"})
        mitig_group["controls"].append(ctrl)

    # Technique (top-level) controls
    control_by_tech = {}
    for tid, t in parsed["techniques"].items():
        # skip subtechniques here; add later under parent
        if t.get("x_mitre_is_subtechnique") or t.get("is_subtechnique"):
            continue
        name = t.get("name", str(tid))
        ext_id = get_external_id(t) if isinstance(t, dict) else None
        ext_or_stix = (ext_id or str(tid).split("--")[-1]).lower()
        ctrl_id = f"atlas-tech-{safe_slug(ext_or_stix)}"

        control = {
            "id": ctrl_id,
            "title": name,
            "props": [
                {"name": "atlas:object-type", "ns": "https://atlas.mitre.org", "value": "technique"},
                {"name": "atlas:source-id", "ns": "https://atlas.mitre.org", "value": str(tid)},
            ],
            "links": [],
            "parts": []
        }
        # description
        desc = t.get("description")
        if desc:
            control["parts"].append({"id": f"{ctrl_id}-desc", "name": "statement", "prose": desc})
        # reference link
        url = get_first_url(t)
        if url:
            control["links"].append({"href": url, "rel": "reference"})
        # tactics
        tacts = parsed["tech_to_tactics"].get(tid, [])
        if tacts:
            control["props"].append({
                "name": "atlas:tactics", "ns": "https://atlas.mitre.org", "value": ",".join(tacts)
            })
        # mitigations (as props to keep validation robust)
        mit_ids = [mit_ctrl_id[mid] for mid in sorted(parsed["tech_to_mitigations"].get(tid, []))]
        if mit_ids:
            control["props"].append({
                "name": "atlas:mitigations", "ns": "https://atlas.mitre.org", "value": ",".join(mit_ids)
            })

        control_by_tech[tid] = control

    # Add subtechniques as nested controls
    for parent_id, children in parsed["parent_to_children"].items():
        parent_ctrl = control_by_tech.get(parent_id)
        if not parent_ctrl:
            # parent might be deprecated or filtered out
            continue
        parent_ctrl.setdefault("controls", [])
        for child_id in children:
            child = parsed["techniques"].get(child_id)
            if not child:
                continue
            ext_id = get_external_id(child)
            ext_or_stix = (ext_id or str(child_id).split("--")[-1]).lower()
            child_ctrl_id = f"atlas-tech-{safe_slug(ext_or_stix)}"
            c = {
                "id": child_ctrl_id,
                "title": child.get("name", str(child_id)),
                "props": [
                    {"name": "atlas:object-type", "ns": "https://atlas.mitre.org", "value": "sub-technique"},
                    {"name": "atlas:source-id", "ns": "https://atlas.mitre.org", "value": str(child_id)},
                ],
                "parts": []
            }
            if child.get("description"):
                c["parts"].append({"id": f"{child_ctrl_id}-desc", "name": "statement", "prose": child["description"]})
            mit_ids = [mit_ctrl_id[mid] for mid in sorted(parsed["tech_to_mitigations"].get(child_id, []))]
            if mit_ids:
                c["props"].append({
                    "name": "atlas:mitigations", "ns": "https://atlas.mitre.org", "value": ",".join(mit_ids)
                })
            parent_ctrl["controls"].append(c)

    # Place technique controls into tactic groups (first tactic wins to avoid duplicate control IDs)
    if not groups_by_short:
        # ensure one group exists even if tactics missing
        groups_by_short["uncategorized"] = {
            "id": "atlas-tactic-uncategorized", "title": "Uncategorized", "controls": []
        }

    for tid, ctrl in control_by_tech.items():
        tacts = parsed["tech_to_tactics"].get(tid, [])
        target_group = groups_by_short.get(tacts[0]) if tacts else groups_by_short.get("uncategorized")
        if target_group is None:
            # create uncategorized on the fly if not present
            groups_by_short["uncategorized"] = {
                "id": "atlas-tactic-uncategorized", "title": "Uncategorized", "controls": []
            }
            target_group = groups_by_short["uncategorized"]
        target_group["controls"].append(ctrl)

    # Assemble groups list
    groups = list(groups_by_short.values())
    groups.append(mitig_group)
    catalog["catalog"]["groups"] = groups
    return catalog


def main():
    ap = argparse.ArgumentParser(description="Convert MITRE ATLAS to OSCAL Catalog (JSON).")
    ap.add_argument("--source", choices=["stix", "yaml"], default="stix",
                    help="Source data format (default: stix).")
    ap.add_argument("--input", help="Path or URL to source file. Defaults to MITRE GitHub raw for the chosen source.")
    ap.add_argument("--out", "-o", default="atlas-oscal-catalog.json", help="Output OSCAL catalog JSON file.")
    ap.add_argument("--oscal-version", default="1.1.3", help="OSCAL version to embed in metadata (default: 1.1.3).")
    args = ap.parse_args()

    source_url = args.input or (DEFAULT_STIX_URL if args.source == "stix" else DEFAULT_YAML_URL)
    raw = fetch_bytes(source_url)

    if args.source == "stix":
        parsed = parse_stix_bundle(raw, source_url=source_url)
    else:
        parsed = parse_yaml(raw, source_url=source_url)

    catalog = build_oscal_catalog(parsed, oscal_version=args.oscal_version)

    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(catalog, f, indent=2, ensure_ascii=False)

    # Basic stats
    n_tactics = len(parsed["tactic_by_shortname"])
    n_techniques = sum(1 for tid, t in parsed["techniques"].items() if not t.get("x_mitre_is_subtechnique") and not t.get("is_subtechnique"))
    n_subtechniques = sum(1 for tid, t in parsed["techniques"].items() if t.get("x_mitre_is_subtechnique") or t.get("is_subtechnique"))
    n_mitigations = len(parsed["mitigations"])
    print(f"Wrote {args.out}")
    print(f"  Tactics:       {n_tactics}")
    print(f"  Techniques:    {n_techniques}")
    print(f"  Subtechniques: {n_subtechniques}")
    print(f"  Mitigations:   {n_mitigations}")


if __name__ == "__main__":
    sys.exit(main())

