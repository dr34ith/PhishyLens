#!/usr/bin/env python3
"""
Build static/mitre.json from MITRE's official Enterprise ATT&CK STIX bundle.

    python scripts/build_mitre.py                         # download latest enterprise-attack.json
    python scripts/build_mitre.py --source enterprise-attack.json

Source: https://github.com/mitre-attack/attack-stix-data (enterprise-attack/enterprise-attack.json)

Output is keyed by technique ID ("T1098", "T1098.004", ...). Every text field is copied from the
bundle; the only transformations are removing "(Citation: ...)" markers / markdown link syntax,
collapsing whitespace, and keeping the first two sentences of the technique description.
Nothing is paraphrased or written by hand.

The single non-technique key "_meta" holds the ATT&CK version and the matrix tactic order
(needed to draw the tactic columns, since ATT&CK v19 split Defense Evasion into Stealth and
Defense Impairment).

ATT&CK v18+ removed the free-text x_mitre_detection field; detection guidance now lives in
Detection Strategies (DET####) and their Analytics. This script reads whichever the bundle has.
"""
import argparse
import hashlib
import json
import os
import re
import sys
import tempfile
import urllib.request
from collections import defaultdict
from datetime import datetime, timezone

SOURCE_URL = ("https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/"
              "enterprise-attack/enterprise-attack.json")
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_OUT = os.path.join(ROOT, "static", "mitre.json")
MAX_ANALYTICS_PER_STRATEGY = 2
MAX_STRATEGIES = 3

# abbreviations that end in "." but do not end a sentence
_ABBREV = ("e.g.", "i.e.", "etc.", "vs.", "Inc.", "Corp.", "Ltd.", "U.S.", "Dr.", "Mr.", "No.", "approx.", "cf.")


def punct(text: str) -> str:
    """PhishyLens house style: no em dashes. A spaced em dash between two parts becomes ': ', any other one a hyphen. Never rewords."""
    return re.sub(r"\s*\u2014\s*", ": ", text or "").replace("\u2014", "-")


def clean(text: str) -> str:
    """Strip citation markers / markdown / HTML code tags; collapse whitespace; house punctuation. Never rewords."""
    if not text:
        return ""
    t = re.sub(r"\(Citation:[^)]*\)", "", punct(text))
    t = re.sub(r"\[([^\]]+)\]\((?:https?://|/)[^)]*\)", r"\1", t)     # [text](url) -> text
    t = re.sub(r"</?code>", "", t)
    t = re.sub(r"\s+", " ", t).strip()
    t = re.sub(r"\s+([.,;:])", r"\1", t)                                 # space left before punctuation by citation removal
    return t


def first_sentences(text: str, n: int = 2) -> str:
    """First n sentences of the opening prose. Stops at a markdown bullet list, and drops a sentence that only
    introduces that list ("...including:"), so no list items get glued into the summary."""
    prose = []
    for para in re.split(r"\n\s*\n", text or ""):
        if re.match(r"\s*[*\-] ", para):
            break
        prose.append(para)
    t = clean(" ".join(prose))
    out, start, i = [], 0, 0
    while i < len(t) and len(out) < n:
        ch = t[i]
        if ch in ".!?" and (i + 1 == len(t) or (t[i + 1] == " " and i + 2 < len(t) and (t[i + 2].isupper() or t[i + 2] in "(\"'"))):
            chunk = t[start:i + 1]
            if not any(chunk.endswith(a) for a in _ABBREV):
                out.append(chunk.strip())
                start = i + 1
        i += 1
    if len(out) < n and start < len(t):
        out.append(t[start:].strip())
    while len(out) > 1 and out[-1].endswith(":"):
        out.pop()
    return " ".join(s for s in out if s)


def ext_id(obj: dict) -> str:
    for r in obj.get("external_references", []):
        if r.get("source_name") == "mitre-attack" and r.get("external_id"):
            return r["external_id"]
    return ""


def ext_url(obj: dict) -> str:
    for r in obj.get("external_references", []):
        if r.get("source_name") == "mitre-attack" and r.get("url"):
            return r["url"]
    return ""


def technique_url(tid: str) -> str:
    base, _, sub = tid.partition(".")
    return f"https://attack.mitre.org/techniques/{base}/{sub}/" if sub else f"https://attack.mitre.org/techniques/{base}/"


def live(obj: dict) -> bool:
    return not obj.get("revoked") and not obj.get("x_mitre_deprecated")


def load_bundle(source: str | None) -> tuple[dict, str, str]:
    if source:
        path, origin = source, f"local file {os.path.basename(source)} (from {SOURCE_URL})"
    else:
        path = os.path.join(tempfile.gettempdir(), "enterprise-attack.json")
        print(f"Downloading {SOURCE_URL} -> {path}", file=sys.stderr)
        urllib.request.urlretrieve(SOURCE_URL, path)
        origin = SOURCE_URL
    with open(path, "rb") as fh:
        raw = fh.read()
    return json.loads(raw), origin, hashlib.sha256(raw).hexdigest()


def build(bundle: dict) -> dict:
    objs = bundle["objects"]
    by_id = {o["id"]: o for o in objs}

    matrix = next(o for o in objs if o["type"] == "x-mitre-matrix" and live(o))
    tactics = [by_id[ref] for ref in matrix["tactic_refs"]]
    tactic_name = {t["x_mitre_shortname"]: t["name"] for t in tactics}
    collection = next((o for o in objs if o["type"] == "x-mitre-collection"), {})

    mitigations, detections = defaultdict(list), defaultdict(list)
    for r in objs:
        if r["type"] != "relationship" or not live(r):
            continue
        src, tgt = by_id.get(r["source_ref"]), by_id.get(r["target_ref"])
        if not src or not tgt or tgt["type"] != "attack-pattern" or not live(src):
            continue
        if r["relationship_type"] == "mitigates" and src["type"] == "course-of-action" and ext_id(src).startswith("M"):
            mitigations[tgt["id"]].append({
                "id": ext_id(src), "name": punct(src["name"]), "url": ext_url(src),
                "description": first_sentences(r.get("description", ""), 1),
            })
        elif r["relationship_type"] == "detects" and src["type"] == "x-mitre-detection-strategy":
            analytics = []
            for aref in src.get("x_mitre_analytic_refs", []):
                a = by_id.get(aref)
                d = clean(a.get("description", "")) if a and live(a) else ""
                if d and d not in analytics:
                    analytics.append(d)
            detections[tgt["id"]].append({
                "id": ext_id(src), "name": punct(src["name"]), "url": ext_url(src),
                "analytics": analytics[:MAX_ANALYTICS_PER_STRATEGY],
            })
        elif r["relationship_type"] == "detects" and src["type"] == "x-mitre-data-component":
            # pre-v18 bundles: data component "detects" technique, guidance in the relationship text
            detections[tgt["id"]].append({"id": "", "name": punct(src["name"]), "url": "",
                                          "analytics": [first_sentences(r.get("description", ""), 2)] if r.get("description") else []})

    out = {}
    for ap in objs:
        if ap["type"] != "attack-pattern" or not live(ap):
            continue
        tid = ext_id(ap)
        if not re.fullmatch(r"T\d{4}(?:\.\d{3})?", tid):
            continue
        phases = [p["phase_name"] for p in ap.get("kill_chain_phases", []) if p.get("kill_chain_name") == "mitre-attack"]
        legacy_detection = clean(ap.get("x_mitre_detection", ""))
        out[tid] = {
            "name": punct(ap["name"]),
            "tactics": [tactic_name.get(p, p) for p in phases],
            "tactic_shortnames": phases,
            "description": first_sentences(ap.get("description", ""), 2),
            "detection": sorted(detections.get(ap["id"], []), key=lambda d: d["id"])[:MAX_STRATEGIES]
                         or ([{"id": "", "name": "Detection", "url": "", "analytics": [first_sentences(legacy_detection, 3)]}] if legacy_detection else []),
            "mitigations": sorted({m["id"]: m for m in mitigations.get(ap["id"], [])}.values(), key=lambda m: m["id"]),
            "platforms": ap.get("x_mitre_platforms", []),
            "is_subtechnique": bool(ap.get("x_mitre_is_subtechnique")),
            "url": technique_url(tid),
        }

    # sub-techniques inherit the parent name as a prefix on attack.mitre.org ("Brute Force: Password Guessing")
    for tid, t in out.items():
        if "." in tid and tid.split(".")[0] in out:
            t["parent_name"] = out[tid.split(".")[0]]["name"]

    meta = {
        "attack_version": collection.get("x_mitre_version", ""),
        "attack_modified": collection.get("modified", ""),
        "domain": "enterprise-attack",
        "tactics": [{"id": ext_id(t), "shortname": t["x_mitre_shortname"], "name": punct(t["name"])} for t in tactics],
        "technique_count": len(out),
    }
    return {"_meta": meta, **dict(sorted(out.items()))}


def write(data: dict, path: str) -> None:
    # one technique per line: small enough to ship, still diff-able between ATT&CK releases
    lines = [f"{json.dumps(k)}: {json.dumps(v, ensure_ascii=False, separators=(',', ':'))}" for k, v in data.items()]
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write("{\n" + ",\n".join(lines) + "\n}\n")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--source", help="local enterprise-attack.json (default: download from GitHub)")
    ap.add_argument("--out", default=DEFAULT_OUT)
    args = ap.parse_args()
    bundle, origin, digest = load_bundle(args.source)
    data = build(bundle)
    data["_meta"].update({"source": origin, "source_sha256": digest,
                          "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")})
    write(data, args.out)
    m = data["_meta"]
    print(f"Wrote {args.out}: ATT&CK v{m['attack_version']}, {m['technique_count']} techniques, "
          f"{len(m['tactics'])} tactics ({os.path.getsize(args.out) // 1024} KB)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
