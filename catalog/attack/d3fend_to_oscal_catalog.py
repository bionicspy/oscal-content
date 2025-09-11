#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Convert MITRE D3FEND (+ ATT&CK links) to an OSCAL Catalog (JSON).

Fixes:
- Prefer d3fend.csv (authoritative techniques list).
- Support CURIEs (e.g., d3f:URLReputationAnalysis) from JSON-LD and mappings.
- Map CURIEs to human page URLs: https://d3fend.mitre.org/technique/<CURIE>/

Usage:
  python d3fend_to_oscal_catalog.py --out d3fend-oscal-catalog.json
  python d3fend_to_oscal_catalog.py --d3fend-version 1.2.0 --oscal-version 1.1.6
"""

import argparse
import csv
import io
import json
import re
import sys
import uuid
from datetime import datetime, timezone
from typing import Dict, List, Tuple, Any, Optional

try:
    import requests
except ImportError:
    print("This script requires the 'requests' package. Install with: pip install requests")
    sys.exit(2)

DEFAULT_D3FEND_VERSION = "1.2.0"
D3FEND_BASE = "https://d3fend.mitre.org/ontologies/d3fend"

ATTACK_TECH_REGEX = re.compile(r"(T\d{4}(?:\.\d{3})?)")
D3F_CURIE_REGEX = re.compile(r"\bd3f:[A-Za-z0-9_]+\b")

def build_default_urls(d3fend_version: str) -> Tuple[str, str, str]:
    jsonld_url = f"{D3FEND_BASE}/{d3fend_version}/d3fend.json"
    mappings_url = f"{D3FEND_BASE}/{d3fend_version}/d3fend-full-mappings.json"
    csv_url = f"{D3FEND_BASE}/{d3fend_version}/d3fend.csv"
    return jsonld_url, mappings_url, csv_url

def http_get_json(url: str) -> Any:
    r = requests.get(url, timeout=90)
    r.raise_for_status()
    return r.json()

def http_get_text(url: str) -> str:
    r = requests.get(url, timeout=90)
    r.raise_for_status()
    return r.text

def curie_to_page_uri(curie: str) -> str:
    # human-readable page URL used by the site
    return f"https://d3fend.mitre.org/technique/{curie}/"

def extract_techniques_from_csv(csv_text: str) -> Dict[str, dict]:
    """
    Parse d3fend.csv for techniques.
    We detect likely columns by header names; robust to minor changes.
    Returns dict keyed by CURIE ('d3f:URLReputationAnalysis').
    """
    f = io.StringIO(csv_text)
    reader = csv.DictReader(f)
    # Heuristic header mapping
    header_map = {h.lower(): h for h in reader.fieldnames or []}

    def get(row, *cands):
        for c in cands:
            h = header_map.get(c.lower())
            if h and row.get(h):
                return row[h].strip()
        return None
    techniques: Dict[str, dict] = {}
    for row in reader:
        # Common column candidates (observed across releases):
        # code: D3-XXX
        code = get(row, "code", "short_code", "shortcode", "d3fend_code", "d3f-code")
        # curie/id: d3f:ThingName
        curie = get(row, "id", "curie", "identifier", "iri", "term")
        # title/label:
        title = get(row, "label", "name", "title", "prefLabel")
        # description/definition:
        desc = get(row, "definition", "description", "comment")
        # domain/tactic:
        domain = get(row, "domain", "tactic", "category")
        # uri/page:
        uri = get(row, "uri", "url", "page", "href")

        # Normalize/mint values
        if curie and not curie.startswith("d3f:") and ":" not in curie and "/" not in curie:
            curie = f"d3f:{curie}"
        if not uri and curie and curie.startswith("d3f:"):
            uri = curie_to_page_uri(curie)
        if not code and curie and title:
            # best-effort pseudo-code if code not provided
            code = "D3-" + "".join([w[0].upper() for w in title.split() if w])[:6]  # not perfect

        if curie and title:
            techniques[curie] = {
                "code": code or curie.replace("d3f:", "D3-"),
                "curie": curie,
                "uri": uri,
                "title": title,
                "description": desc,
                "domain": domain,
            }
    return techniques

def deep_iter_nodes(obj):
    """Yield every dict node within a JSON structure (for JSON-LD fallback)."""
    if isinstance(obj, dict):
        yield obj
        for v in obj.values():
            yield from deep_iter_nodes(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from deep_iter_nodes(v)

def extract_techniques_from_jsonld(jsonld: dict) -> Dict[str, dict]:
    """
    Fallback in case CSV is unavailable: recognize techniques by CURIE @id, d3fend:code, or presence of a technique-like label.
    """
    techniques: Dict[str, dict] = {}
    label_keys = ["rdfs:label", "skos:prefLabel", "label", "name", "title"]
    desc_keys  = ["rdfs:comment", "skos:definition", "definition", "description", "comment"]

    for node in deep_iter_nodes(jsonld):
        if not isinstance(node, dict):
            continue

        node_id = node.get("@id") or node.get("id") or node.get("iri") or node.get("identifier")
        if isinstance(node_id, str) and node_id.startswith("d3f:"):
            curie = node_id
        elif isinstance(node_id, str) and "/technique/" in node_id:
            # Extract CURIE from page URL if present
            m = re.search(r"/technique/(d3f:[^/]+)/?", node_id)
            curie = m.group(1) if m else None
        else:
            curie = None

        # Detect code
        code = None
        for k in ["d3fend:code", "code", "short_code", "shortcode"]:
            v = node.get(k)
            if isinstance(v, str) and v.strip():
                code = v.strip()
                break

        if not (curie or code):
            continue  # not clearly a technique

        # Title/description
        def first_nonempty(keys):
            for k in keys:
                v = node.get(k)
                if isinstance(v, str) and v.strip():
                    return v.strip()
                if isinstance(v, dict) and "@value" in v and str(v["@value"]).strip():
                    return str(v["@value"]).strip()
            return None

        title = first_nonempty(label_keys) or (curie.split(":")[1] if curie else code)
        desc  = first_nonempty(desc_keys)
        uri   = curie_to_page_uri(curie) if curie else None

        # Domain (best-effort)
        domain = None
        for k in ["d3fend:domain", "d3fend:tactic", "domain", "tactic", "category"]:
            v = node.get(k)
            if isinstance(v, str) and v.strip():
                domain = v.split("/")[-1].title() if "/" in v else v
                break

        if curie or code:
            key = curie or code
            techniques[key] = {
                "code": code or (curie.replace("d3f:", "D3-") if curie else key),
                "curie": curie,
                "uri": uri,
                "title": title,
                "description": desc,
                "domain": domain,
            }

    # Normalize keys to CURIE where possible
    normalized: Dict[str, dict] = {}
    for k, t in techniques.items():
        curie = t.get("curie")
        if curie:
            normalized[curie] = t
    return normalized

def extract_attack_links_from_mappings(mappings_json: dict,
                                       known_curie_set: Optional[set] = None,
                                       known_page_set: Optional[set] = None) -> Dict[str, List[str]]:
    """
    Build { technique_curie -> [Txxxx, ...] } from SPARQL JSON mappings.
    Accept CURIEs or human page URLs in the bindings and normalize.
    """
    curie_to_attack: Dict[str, List[str]] = {}

    results = mappings_json.get("results", {}).get("bindings", [])
    if not isinstance(results, list):
        return curie_to_attack
    def collect_attack_ids(value: str) -> List[str]:
        return ATTACK_TECH_REGEX.findall(value or "")

    def collect_d3f_curie(value: str) -> List[str]:
        curies = D3F_CURIE_REGEX.findall(value or "")
        from_page = []
        if "d3fend.mitre.org/technique/" in value:
            m = re.search(r"/technique/(d3f:[^/]+)/?", value)
            if m:
                from_page.append(m.group(1))
        return sorted(set(curies + from_page))

    for b in results:
        # flatten
        vals = []
        for v in b.values():
            if isinstance(v, dict) and "value" in v:
                vals.append(str(v["value"]))
            elif isinstance(v, str):
                vals.append(v)
        if not vals:
            continue

        tids = sorted(set([tid for v in vals for tid in collect_attack_ids(v)]))
        if not tids:
            continue

        curies = sorted(set([c for v in vals for c in collect_d3f_curie(v)]))
        # Optionally filter to known techniques to avoid over-greedy matches
        if known_curie_set:
            curies = [c for c in curies if c in known_curie_set]

        for c in curies:
            curie_to_attack.setdefault(c, [])
            for tid in tids:
                if tid not in curie_to_attack[c]:
                    curie_to_attack[c].append(tid)

    return curie_to_attack

def group_key(domain: Optional[str]) -> str:
    if isinstance(domain, str):
        d = domain.strip().lower()
        if d.startswith("harden"):  return "harden"
        if d.startswith("detect"):  return "detect"
        if d.startswith("isolate"): return "isolate"
        if d.startswith("deceive"): return "deceive"
        if d.startswith("evict"):   return "evict"
    return "all"

def build_oscal_catalog(techniques_by_curie: Dict[str, dict],
                        curie_to_attack: Dict[str, List[str]],
                        oscal_version: str,
                        d3fend_version: str) -> dict:
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    catalog_uuid = str(uuid.uuid4())

    groups = {
        "harden":  {"id": "d3fend-harden",  "title": "D3FEND – Harden",  "controls": []},
        "detect":  {"id": "d3fend-detect",  "title": "D3FEND – Detect",  "controls": []},
        "isolate": {"id": "d3fend-isolate", "title": "D3FEND – Isolate", "controls": []},
        "deceive": {"id": "d3fend-deceive", "title": "D3FEND – Deceive", "controls": []},
        "evict":   {"id": "d3fend-evict",   "title": "D3FEND – Evict",   "controls": []},
        "all":     {"id": "d3fend-all",     "title": "D3FEND – All Techniques", "controls": []},
    }

    for curie, t in sorted(techniques_by_curie.items(), key=lambda kv: kv[1].get("code","")):
        code = t.get("code") or curie
        gk = group_key(t.get("domain"))
        c = {
            "id": code,
            "title": t.get("title") or code,
            "props": [
                {"name": "d3fend:curie", "value": curie},
                {"name": "d3fend:code",  "value": code},
            ],
            "links": [],
            "parts": [],
        }
        if t.get("uri"):
            c["props"].append({"name": "d3fend:uri", "value": t["uri"]})
            c["links"].append({"href": t["uri"], "rel": "reference", "text": "MITRE D3FEND Technique"})
        if t.get("domain"):
            c["props"].append({"name": "d3fend:domain", "value": str(t["domain"])})

        if t.get("description"):
            c["parts"].append({
                "id": f"{code}-desc",
                "name": "guidance",
                "prose": t["description"]
            })

        for tid in sorted(set(curie_to_attack.get(curie, []))):
            c["links"].append({
                "href": f"https://attack.mitre.org/techniques/{tid}/",
                "rel": "related-attack-technique",
                "text": tid
            })

        groups[gk]["controls"].append(c)

    final_groups = [g for k, g in groups.items() if k == "all" or g["controls"]]

    catalog = {
        "catalog": {
            "uuid": catalog_uuid,
            "metadata": {
                "title": f"MITRE D3FEND Catalog (v{d3fend_version})",
                "last-modified": now,
                "version": d3fend_version,
                "oscal-version": oscal_version,
                "props": [
                    {"name": "source",    "value": "https://d3fend.mitre.org/"},
                    {"name": "generator", "value": "d3fend_to_oscal_catalog.py"},
                ],
                "remarks": "Generated from D3FEND d3fend.csv and full mappings; CURIEs mapped to technique pages."
            },
            "groups": final_groups
        }
    }
    return catalog

def main():
    ap = argparse.ArgumentParser(description="Convert MITRE D3FEND (+ATT&CK links) to an OSCAL Catalog (JSON).")
    ap.add_argument("--out", required=True, help="Output OSCAL Catalog JSON file path.")
    ap.add_argument("--d3fend-version", default=DEFAULT_D3FEND_VERSION, help="D3FEND release version, e.g., 1.2.0")
    ap.add_argument("--oscal-version", default="1.1.6", help="OSCAL version string to place in metadata.oscal-version.")
    ap.add_argument("--jsonld-url", default=None, help="Override: D3FEND JSON-LD URL.")
    ap.add_argument("--mappings-url", default=None, help="Override: D3FEND full mappings (SPARQL JSON) URL.")
    ap.add_argument("--csv-url", default=None, help="Override: D3FEND CSV techniques URL.")
    args = ap.parse_args()

    jsonld_url, mappings_url, csv_url = build_default_urls(args.d3fend_version)
    if args.jsonld_url:   jsonld_url = args.jsonld_url
    if args.mappings_url: mappings_url = args.mappings_url
    if args.csv_url:      csv_url = args.csv_url

    # 1) Techniques from CSV (preferred)
    print(f"[+] Downloading D3FEND CSV: {csv_url}")
    techniques_by_curie = {}
    try:
        csv_text = http_get_text(csv_url)
        techniques_by_curie = extract_techniques_from_csv(csv_text)
        print(f"    Found {len(techniques_by_curie)} techniques from CSV.")
    except Exception as e:
        print(f"    [!] CSV load failed ({e}); falling back to JSON-LD.")

    # 2) Fallback to JSON-LD if CSV missing or empty
    if not techniques_by_curie:
        print(f"[+] Downloading D3FEND JSON-LD: {jsonld_url}")
        try:
            d3f_jsonld = http_get_json(jsonld_url)
            techniques_by_curie = extract_techniques_from_jsonld(d3f_jsonld)
            print(f"    Found {len(techniques_by_curie)} techniques from JSON-LD.")
        except Exception as e:
            print(f"    [!] JSON-LD load failed: {e}")

    # 3) ATT&CK links
    print(f"[+] Downloading D3FEND inferred mappings: {mappings_url}")
    curie_to_attack: Dict[str, List[str]] = {}
    try:
        d3f_mappings = http_get_json(mappings_url)
        known_curies = set(techniques_by_curie.keys())
        curie_to_attack = extract_attack_links_from_mappings(d3f_mappings, known_curie_set=known_curies)
        linked = sum(1 for c in known_curies if c in curie_to_attack and curie_to_attack[c])
        print(f"    Found ATT&CK links for {linked} techniques.")
    except Exception as e:
        print(f"    [!] Mappings load/parse failed: {e}")

    # 4) Build OSCAL catalog
    print("[+] Building OSCAL catalog...")
    catalog = build_oscal_catalog(techniques_by_curie, curie_to_attack, args.oscal_version, args.d3fend_version)

    print(f"[+] Writing: {args.out}")
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(catalog, f, indent=2, ensure_ascii=False)

    print("[✓] Done.")

if __name__ == "__main__":
    main()

