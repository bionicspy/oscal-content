#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
atlas_to_oscal.py
Convert MITRE ATLAS techniques & mitigations to an OSCAL Catalog (JSON).

Highlights
- Source: ATLAS STIX 2.1 (default) or ATLAS.yaml
- Groups per tactic; technique controls (with nested subtechniques)
- Mitigations group with one control per mitigation (with prose)
- Technique/subtechnique controls include STIX creation/update metadata (created, modified, created-by, version)
- external_id added as a label prop (techniques, subtechniques, mitigations)
- Metadata includes roles/parties/responsible-parties:
  * MITRE (creator, point-of-contact)
  * University of Toronto (oscal-author)
- Back-matter with source citations (resources) and SHA-256 hashes in rlinks
- Timezone-aware last-modified (Python 3.12+ friendly)
- ATLAS dataset version recorded (from ATLAS.yaml) and added to metadata.props and metadata.revisions
- Version history: by default the last 5 ATLAS Data releases are fetched from GitHub and merged into metadata.revisions
  (override with --revisions-from-releases N; set 0 to disable)
- --carry-revisions-from lets you merge prior metadata.revisions into the new output

References:
- ATLAS.yaml top-level exposes the data release version.  # https://github.com/mitre-atlas/atlas-data
- STIX data in atlas-navigator-data is generated from atlas-data.  # https://github.com/mitre-atlas/atlas-navigator-data
- OSCAL metadata.revisions[] is the schema place for version history.  # https://pages.nist.gov/OSCAL-Reference/models/develop/complete/json-outline/
- ATLAS Data releases page (human-readable history).  # https://github.com/mitre-atlas/atlas-data/releases
- YAML media type guidance (application/yaml).  # https://github.com/usnistgov/OSCAL/issues/1255
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import re
import sys
import uuid
import urllib.request

try:
    import yaml  # Optional, only needed for --source yaml or when parsing alt YAML for version
except Exception:
    yaml = None


DEFAULT_STIX_URL = (
    "https://raw.githubusercontent.com/mitre-atlas/atlas-navigator-data/main/dist/stix-atlas.json"
)
DEFAULT_YAML_URL = (
    "https://raw.githubusercontent.com/mitre-atlas/atlas-data/main/dist/ATLAS.yaml"
)
ATLAS_HOMEPAGE = "https://atlas.mitre.org"
ATLAS_RELEASES = "https://github.com/mitre-atlas/atlas-data/releases"


def fetch_bytes(path_or_url: str) -> bytes:
    """Fetch bytes from a local path or HTTP(S) URL."""
    if re.match(r"^https?://", path_or_url, flags=re.I):
        with urllib.request.urlopen(path_or_url) as r:
            return r.read()
    with open(path_or_url, "rb") as f:
        return f.read()


def fetch_json(url: str, headers: dict | None = None) -> dict | list:
    """Fetch JSON from a URL using urllib with a default User-Agent."""
    req = urllib.request.Request(url, headers=headers or {"User-Agent": "atlas-to-oscal/1.0"})
    with urllib.request.urlopen(req) as r:
        return json.loads(r.read().decode("utf-8"))


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def safe_slug(text: str) -> str:
    """URL/ID-safe slug."""
    return re.sub(r"[^a-z0-9]+", "-", (text or "").lower()).strip("-")


def get_external_id(stix_obj: dict) -> str | None:
    """Return first external_id if present (e.g., T####, T####.###, M####)."""
    for ref in stix_obj.get("external_references", []):
        if "external_id" in ref:
            return ref["external_id"]
    return None


def get_first_url(stix_obj: dict) -> str | None:
    """Return first external reference URL if present."""
    for ref in stix_obj.get("external_references", []):
        if "url" in ref:
            return ref["url"]
    return None


def parse_stix_bundle(stix_bytes: bytes, source_url: str | None = None) -> dict:
    """Parse ATLAS STIX 2.1 bundle and build intermediate structures."""
    bundle = json.loads(stix_bytes.decode("utf-8"))
    objs = bundle.get("objects", [])

    identities = {}
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
        elif t == "identity":
            if o.get("id"):
                identities[o["id"]] = o

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
        tech_to_tactics[tid] = list(dict.fromkeys([s for s in tactic_shortnames if s]))

    # Parent technique -> [subtechniques]; technique -> set(mitigation IDs)
    parent_to_children = {}
    tech_to_mitigations = {}
    for r in relationships:
        rtype = r.get("relationship_type")
        src = r.get("source_ref")
        tgt = r.get("target_ref")
        if rtype == "subtechnique-of":
            parent_to_children.setdefault(tgt, []).append(src)
        elif rtype == "mitigates":
            if tgt in techniques and src in mitigations:
                tech_to_mitigations.setdefault(tgt, set()).add(src)

    for k in list(parent_to_children.keys()):
        parent_to_children[k] = sorted(set(parent_to_children[k]))

    return {
        "source_url": source_url,
        "bundle": bundle,
        "identities": identities,
        "tactics_by_id": tactics_by_id,
        "tactic_by_shortname": tactic_by_shortname,
        "techniques": techniques,
        "mitigations": mitigations,
        "tech_to_tactics": tech_to_tactics,
        "parent_to_children": parent_to_children,
        "tech_to_mitigations": tech_to_mitigations,
    }


def parse_yaml(atlas_yaml_bytes: bytes, source_url: str | None = None) -> dict:
    """Parse ATLAS.yaml and return structures plus dataset version."""
    if yaml is None:
        raise RuntimeError("PyYAML is required for --source yaml. pip install pyyaml")
    data = yaml.safe_load(atlas_yaml_bytes.decode("utf-8"))

    # dataset metadata (present at top level per atlas-data README)
    atlas_version = data.get("version")
    atlas_name = data.get("name")
    atlas_id = data.get("id")

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
        "identities": {},
        "tactics_by_id": tactics_by_id,
        "tactic_by_shortname": tactic_by_shortname,
        "techniques": tech_map,
        "mitigations": mit_map,
        "tech_to_tactics": tech_to_tactics,
        "parent_to_children": parent_to_children,
        "tech_to_mitigations": {},
        # dataset metadata
        "atlas_version": atlas_version,
        "atlas_name": atlas_name,
        "atlas_id": atlas_id,
    }


def stix_meta_props(o: dict, identities: dict | None = None, ns: str = "https://atlas.mitre.org") -> list[dict]:
    """Build OSCAL props from common STIX metadata on an SDO."""
    props = []
    for fld in ("created", "modified"):
        if o.get(fld):
            props.append({"name": f"atlas:{fld}", "ns": ns, "value": o[fld]})
    cbr = o.get("created_by_ref")
    if cbr:
        props.append({"name": "atlas:created-by-ref", "ns": ns, "value": cbr})
        if identities and identities.get(cbr, {}).get("name"):
            props.append({"name": "atlas:created-by", "ns": ns, "value": identities[cbr]["name"]})
    if o.get("revoked") is True:
        props.append({"name": "atlas:revoked", "ns": ns, "value": "true"})
    if o.get("x_mitre_deprecated") is True or o.get("deprecated") is True:
        props.append({"name": "atlas:deprecated", "ns": ns, "value": "true"})
    ver = o.get("x_mitre_version") or o.get("version")
    if ver:
        props.append({"name": "atlas:version", "ns": ns, "value": str(ver)})
    return props


def resource_with_hash(title: str, href: str, media_type: str, content_bytes: bytes) -> dict:
    """Build a back-matter resource with rlink and sha-256 hash."""
    return {
        "uuid": str(uuid.uuid4()),
        "title": title,
        "rlinks": [{
            "href": href,
            "media-type": media_type,
            "hashes": [{
                "algorithm": "sha-256",
                "value": sha256_hex(content_bytes)
            }]
        }]
    }


def extract_atlas_yaml_version(atlas_yaml_bytes: bytes) -> str | None:
    """Best-effort parse of ATLAS.yaml to read dataset version."""
    if yaml is None:
        return None
    try:
        data = yaml.safe_load(atlas_yaml_bytes.decode("utf-8"))
        return data.get("version")
    except Exception:
        return None


def revisions_from_atlas_releases(limit: int = 5) -> list[dict]:
    """
    Build OSCAL revision entries from the last N GitHub releases of mitre-atlas/atlas-data.
    Each revision includes version (tag_name), published timestamp, and a link to the release.
    """
    if limit is None or int(limit) <= 0:
        return []
    url = "https://api.github.com/repos/mitre-atlas/atlas-data/releases"
    headers = {"User-Agent": "atlas-to-oscal/1.0"}
    token = os.environ.get("GITHUB_TOKEN")  # optional to raise rate limit
    if token:
        headers["Authorization"] = f"Bearer {token}"
    try:
        releases = fetch_json(url, headers=headers)
    except Exception:
        return []
    revs = []
    for rel in releases[:int(limit)]:
        version = rel.get("tag_name") or rel.get("name") or ""
        if not version:
            continue
        rev = {
            "title": "MITRE ATLAS Data Release",
            "version": str(version),
            # GitHub returns ISO 8601 with 'Z' which is valid for OSCAL
            "published": rel.get("published_at"),
            "links": [
                {"href": rel.get("html_url"), "rel": "reference"}
            ],
            "props": [
                {"name": "release-id", "ns": "https://atlas.mitre.org", "value": str(rel.get("id"))},
                {"name": "prerelease", "ns": "https://atlas.mitre.org",
                 "value": str(rel.get("prerelease", False)).lower()}
            ],
            "remarks": (rel.get("name") or "")
        }
        revs.append(rev)
    return revs


def build_oscal_catalog(parsed: dict, source_kind: str, source_bytes: bytes,
                        oscal_version: str = "1.1.3", title: str | None = None,
                        carry_revisions_from: str | None = None,
                        releases_limit: int | None = 5) -> dict:
    """Construct an OSCAL catalog with groups, controls, back-matter, and version history."""
    # Timezone-aware UTC (and normalized to trailing Z)
    now = dt.datetime.now(dt.UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")
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
                    {"href": ATLAS_HOMEPAGE, "rel": "source"},
                ]
            },
            "groups": []
        }
    }
    if parsed.get("source_url"):
        catalog["catalog"]["metadata"]["links"].append(
            {"href": parsed["source_url"], "rel": "source"}
        )

    # --- Roles, parties, responsible-parties ---
    catalog["catalog"]["metadata"]["roles"] = [
        {"id": "creator", "title": "Content Creator"},
        {"id": "point-of-contact", "title": "Point of Contact"},
        {"id": "oscal-author", "title": "OSCAL Author"}
    ]
    catalog["catalog"]["metadata"]["parties"] = [
        {
            "uuid": "123e4567-e89b-12d3-a456-426614174000",
            "type": "organization",
            "name": "MITRE Corporation",
            "short-name": "MITRE",
            "email-addresses": ["atlas@mitre.org"],
            "links": [{"href": ATLAS_HOMEPAGE, "rel": "website"}]
        },
        {
            "uuid": "7525e825-925e-4075-b812-bb514522fb97",
            "type": "organization",
            "name": "University of Toronto",
            "email-addresses": ["security@utoronto.ca"],
            "addresses": [
                {
                    "addr-lines": [
                        "University of Toronto",
                        "27 King's College Circle"
                    ],
                    "city": "Toronto",
                    "state": "ON",
                    "postal-code": "M5S"
                }
            ]
        }
    ]
    # IMPORTANT: JSON uses "party-uuids" (plural)
    catalog["catalog"]["metadata"]["responsible-parties"] = [
        {"role-id": "creator",          "party-uuids": ["123e4567-e89b-12d3-a456-426614174000"]},
        {"role-id": "point-of-contact", "party-uuids": ["123e4567-e89b-12d3-a456-426614174000"]},
        {"role-id": "oscal-author",     "party-uuids": ["7525e825-925e-4075-b812-bb514522fb97"]}
    ]
    # --- end parties/roles ---

    # --- ATLAS dataset version (from YAML), with history ---
    md = catalog["catalog"]["metadata"]
    md.setdefault("props", [])

    atlas_version = None
    atlas_version_source = None
    atlas_version_media = None
    atlas_yaml_bytes = None

    if source_kind == "yaml":
        atlas_version = parsed.get("atlas_version")
        atlas_version_source = parsed.get("source_url")
        atlas_version_media = "application/yaml"
    else:
        # Attempt to fetch ATLAS.yaml and parse its version (STIX source doesn't advertise a global version)
        try:
            atlas_yaml_bytes = fetch_bytes(DEFAULT_YAML_URL)
            atlas_version = extract_atlas_yaml_version(atlas_yaml_bytes)
            atlas_version_source = DEFAULT_YAML_URL
            atlas_version_media = "application/yaml"
        except Exception:
            atlas_version = None

    if atlas_version:
        # Add namespaced prop for quick access
        md["props"].append({
            "name": "atlas:data-version", "ns": "https://atlas.mitre.org", "value": str(atlas_version)
        })

        # Prepare a revision entry for the dataset
        dataset_rev = {
            "title": "MITRE ATLAS Data",
            "version": str(atlas_version),
            # timestamps optional here (no reliable release timestamp via raw fetch)
            "props": [
                {"name": "atlas:source-kind", "ns": "https://atlas.mitre.org", "value": source_kind},
                {"name": "atlas:source-url", "ns": "https://atlas.mitre.org", "value": str(atlas_version_source)},
            ],
            "links": [
                {"href": str(atlas_version_source), "rel": "source"},
                {"href": ATLAS_RELEASES, "rel": "reference"}
            ],
            "remarks": "ATLAS dataset version as recorded at generation time."
        }

        # Add source hash if we have the bytes
        try:
            if source_kind == "yaml" and isinstance(source_bytes, (bytes, bytearray)):
                dataset_rev["props"].append({
                    "name": "atlas:source-hash", "ns": "https://atlas.mitre.org",
                    "value": sha256_hex(source_bytes)
                })
            elif atlas_yaml_bytes:
                dataset_rev["props"].append({
                    "name": "atlas:source-hash", "ns": "https://atlas.mitre.org",
                    "value": sha256_hex(atlas_yaml_bytes)
                })
            if atlas_version_media:
                dataset_rev["props"].append({
                    "name": "media-type", "ns": "https://atlas.mitre.org",
                    "value": atlas_version_media
                })
        except Exception:
            pass

        md.setdefault("revisions", [])
        md["revisions"].append(dataset_rev)

    # Also record this OSCAL export as a revision entry (use metadata.version)
    export_rev = {
        "title": "OSCAL Export (atlas_to_oscal)",
        "version": md["version"],
        "last-modified": md["last-modified"],
        "props": [
            {"name": "generator", "ns": "https://atlas.mitre.org", "value": "atlas_to_oscal.py"},
        ]
    }
    md.setdefault("revisions", [])
    md["revisions"].append(export_rev)

    # Append latest ATLAS releases from GitHub to revision history (default 5)
    if releases_limit and int(releases_limit) > 0:
        fetched_revs = revisions_from_atlas_releases(int(releases_limit))
        if fetched_revs:
            existing = {(r.get("title"), r.get("version")) for r in md.get("revisions", [])}
            for r in fetched_revs:
                key = (r.get("title"), r.get("version"))
                if key not in existing:
                    md["revisions"].append(r)

    # Tactic groups
    groups_by_short = {}
    for shortname, tac in parsed.get("tactic_by_shortname", {}).items():
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

    # Mitigation controls (with label + prose)
    mit_ctrl_id = {}
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
            "links": [],
            "parts": []
        }
        if isinstance(m, dict):
            ctrl["props"].extend(stix_meta_props(m, identities=parsed.get("identities")))
            if ext_id:
                ctrl["props"].append({"name": "label", "ns": "https://atlas.mitre.org", "value": ext_id})
            if m.get("description"):
                ctrl["parts"].append({
                    "id": f"{ctrl_id}-desc",
                    "name": "statement",
                    "prose": m["description"]
                })
        url = get_first_url(m) if isinstance(m, dict) else None
        if url:
            ctrl["links"].append({"href": url, "rel": "reference"})
        mitig_group["controls"].append(ctrl)

    # Technique (top-level) controls
    control_by_tech = {}
    for tid, t in parsed["techniques"].items():
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
        control["props"].extend(stix_meta_props(t, identities=parsed.get("identities")))
        if ext_id:
            control["props"].append({"name": "label", "ns": "https://atlas.mitre.org", "value": ext_id})

        desc = t.get("description")
        if desc:
            control["parts"].append({"id": f"{ctrl_id}-desc", "name": "statement", "prose": desc})
        url = get_first_url(t)
        if url:
            control["links"].append({"href": url, "rel": "reference"})
        tacts = parsed["tech_to_tactics"].get(tid, [])
        if tacts:
            control["props"].append({
                "name": "atlas:tactics", "ns": "https://atlas.mitre.org", "value": ",".join(tacts)
            })
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
            continue
        parent_ctrl.setdefault("controls", [])
        for child_id in children:
            child = parsed["techniques"].get(child_id)
            if not child:
                continue
            ext_id_child = get_external_id(child)
            ext_or_stix = (ext_id_child or str(child_id).split("--")[-1]).lower()
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
            c["props"].extend(stix_meta_props(child, identities=parsed.get("identities")))
            if ext_id_child:
                c["props"].append({"name": "label", "ns": "https://atlas.mitre.org", "value": ext_id_child})
            if child.get("description"):
                c["parts"].append({"id": f"{child_ctrl_id}-desc", "name": "statement", "prose": child["description"]})
            mit_ids = [mit_ctrl_id[mid] for mid in sorted(parsed["tech_to_mitigations"].get(child_id, []))]
            if mit_ids:
                c["props"].append({
                    "name": "atlas:mitigations", "ns": "https://atlas.mitre.org", "value": ",".join(mit_ids)
                })
            parent_ctrl["controls"].append(c)

    # Place technique controls into tactic groups
    if not groups_by_short:
        groups_by_short["uncategorized"] = {
            "id": "atlas-tactic-uncategorized", "title": "Uncategorized", "controls": []
        }

    for tid, ctrl in control_by_tech.items():
        tacts = parsed["tech_to_tactics"].get(tid, [])
        target_group = groups_by_short.get(tacts[0]) if tacts else groups_by_short.get("uncategorized")
        if target_group is None:
            groups_by_short["uncategorized"] = {
                "id": "atlas-tactic-uncategorized", "title": "Uncategorized", "controls": []
            }
            target_group = groups_by_short["uncategorized"]
        target_group["controls"].append(ctrl)

    groups = list(groups_by_short.values())
    groups.append(mitig_group)
    catalog["catalog"]["groups"] = groups

    # -------------------------------
    # Back-matter with source citations
    # -------------------------------
    back_matter = {"resources": []}

    # Primary data source (exact file used)
    if parsed.get("source_url") and source_bytes:
        media = "application/json" if source_kind == "stix" else "application/yaml"
        title_src = "MITRE ATLAS STIX 2.1 (stix-atlas.json)" if source_kind == "stix" \
                    else "MITRE ATLAS Data (ATLAS.yaml)"
        try:
            back_matter["resources"].append(
                resource_with_hash(title_src, parsed["source_url"], media, source_bytes)
            )
        except Exception:
            pass  # skipping citation if hashing fails

    # Alternate format (fetch & hash)
    try:
        if source_kind == "stix":
            alt_bytes = fetch_bytes(DEFAULT_YAML_URL)
            back_matter["resources"].append(
                resource_with_hash("MITRE ATLAS Data (ATLAS.yaml)", DEFAULT_YAML_URL, "application/yaml", alt_bytes)
            )
        else:
            alt_bytes = fetch_bytes(DEFAULT_STIX_URL)
            back_matter["resources"].append(
                resource_with_hash("MITRE ATLAS STIX 2.1 (stix-atlas.json)", DEFAULT_STIX_URL, "application/json", alt_bytes)
            )
    except Exception:
        pass

    # ATLAS homepage (HTML) as an additional citation
    try:
        homepage_bytes = fetch_bytes(ATLAS_HOMEPAGE)
        back_matter["resources"].append(
            resource_with_hash("MITRE ATLAS Website", ATLAS_HOMEPAGE, "text/html", homepage_bytes)
        )
    except Exception:
        pass

    if back_matter["resources"]:
        catalog["catalog"]["back-matter"] = back_matter

    # --- carry revisions from previous catalog if requested (to build true history) ---
    if carry_revisions_from:
        try:
            with open(carry_revisions_from, "r", encoding="utf-8") as prevf:
                prev = json.load(prevf)
            prev_revs = prev.get("catalog", {}).get("metadata", {}).get("revisions", [])
            if prev_revs:
                # merge unique by (title, version)
                existing = {(r.get("title"), r.get("version")) for r in md.get("revisions", [])}
                for r in prev_revs:
                    key = (r.get("title"), r.get("version"))
                    if key not in existing:
                        md["revisions"].append(r)
                        existing.add(key)
        except Exception:
            pass
    # -------------------------------------------------------------------------------

    return catalog


def main():
    ap = argparse.ArgumentParser(description="Convert MITRE ATLAS to OSCAL Catalog (JSON).")
    ap.add_argument("--source", choices=["stix", "yaml"], default="stix",
                    help="Source data format (default: stix).")
    ap.add_argument("--input", help="Path or URL to source file. Defaults to MITRE GitHub raw for the chosen source.")
    ap.add_argument("--out", "-o", default="atlas-oscal-catalog.json", help="Output OSCAL catalog JSON file.")
    ap.add_argument("--oscal-version", default="1.1.3", help="OSCAL version to embed in metadata (default: 1.1.3).")
    ap.add_argument("--revisions-from-releases", type=int, default=5,
                    help="Fetch the last N ATLAS releases (default: 5). Set to 0 to disable.")
    ap.add_argument("--carry-revisions-from",
                    help="Path to an existing OSCAL catalog JSON to merge its metadata.revisions into the new output.")
    args = ap.parse_args()

    source_url = args.input or (DEFAULT_STIX_URL if args.source == "stix" else DEFAULT_YAML_URL)
    raw = fetch_bytes(source_url)

    if args.source == "stix":
        parsed = parse_stix_bundle(raw, source_url=source_url)
    else:
        parsed = parse_yaml(raw, source_url=source_url)

    catalog = build_oscal_catalog(
        parsed, source_kind=args.source, source_bytes=raw,
        oscal_version=args.oscal_version,
        carry_revisions_from=args.carry_revisions_from,
        releases_limit=args.revisions_from_releases
    )

    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(catalog, f, indent=2, ensure_ascii=False)

    n_tactics = len(parsed.get("tactic_by_shortname", {}))
    n_techniques = sum(1 for _, t in parsed["techniques"].items()
                       if not t.get("x_mitre_is_subtechnique") and not t.get("is_subtechnique"))
    n_subtechniques = sum(1 for _, t in parsed["techniques"].items()
                          if t.get("x_mitre_is_subtechnique") or t.get("is_subtechnique"))
    n_mitigations = len(parsed["mitigations"])
    print(f"Wrote {args.out}")
    print(f"  Tactics:       {n_tactics}")
    print(f"  Techniques:    {n_techniques}")
    print(f"  Subtechniques: {n_subtechniques}")
    print(f"  Mitigations:   {n_mitigations}")


if __name__ == "__main__":
    sys.exit(main())

