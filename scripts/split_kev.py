#!/usr/bin/env python3
"""Zerlegt den KEV-Katalog in eine JSON-Datei pro CVE: YYYY/CVE-YYYY-NNNN.json"""
import datetime
import json
import re
import sys
from pathlib import Path

CVE_RE = re.compile(r"^CVE-(\d{4})-\d{4,}$")

source = Path(sys.argv[1])
catalog = json.loads(source.read_text(encoding="utf-8"))
vulns = catalog.get("vulnerabilities", [])
today = datetime.datetime.now(datetime.timezone.utc).date().isoformat()
years = {}      # Jahr -> {CVE-ID: dateAdded}
touched = set() # CVEs, die in diesem Lauf neu geschrieben wurden

if not vulns:
    sys.exit("Katalog enthält keine Einträge, Abbruch")
if catalog.get("count") != len(vulns):
    print(f"Warnung: count={catalog.get('count')}, aber {len(vulns)} Einträge", file=sys.stderr)

new = updated = unchanged = skipped = 0
for v in vulns:
    cve = v["cveID"].strip()
    m = CVE_RE.match(cve)
    if not m:
        print(f"Übersprungen (ungültige ID): {cve}", file=sys.stderr)
        skipped += 1
        continue

    target = Path(m.group(1)) / f"{cve}.json"
    years.setdefault(m.group(1), {})[cve] = v["dateAdded"]
    content = json.dumps(v, separators=(",", ":"), ensure_ascii=False) + "\n"

    if target.exists():
        if target.read_text(encoding="utf-8") == content:
            unchanged += 1
            continue
        updated += 1
    else:
        new += 1

    target.parent.mkdir(exist_ok=True)
    target.write_text(content, encoding="utf-8")
    touched.add(cve)

for year, items in years.items():
    index_path = Path(year) / "index.json"
    entries = {}
    if index_path.exists():
        old = json.loads(index_path.read_text(encoding="utf-8"))
        entries = {e["id"]: e for e in old["cves"]}

    for cve, added in items.items():
        if cve in touched:
            entries[cve] = {"id": cve, "dateAdded": added, "updated": today}
        elif cve not in entries:
            entries[cve] = {"id": cve, "dateAdded": added, "updated": added}

    cves = sorted(entries.values(), key=lambda e: int(e["id"].split("-")[2]))
    index = {
        "year": int(year),
        "count": len(cves),
        "updated": max(e["updated"] for e in cves),
        "cves": cves,
    }
    content = json.dumps(index, separators=(",", ":"), ensure_ascii=False) + "\n"
    if not index_path.exists() or index_path.read_text(encoding="utf-8") != content:
        index_path.write_text(content, encoding="utf-8")

print(f"Katalog {catalog.get('catalogVersion')}: {new} neu, {updated} geändert, "
      f"{unchanged} unverändert, {skipped} übersprungen")
