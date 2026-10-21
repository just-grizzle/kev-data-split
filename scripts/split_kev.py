#!/usr/bin/env python3
"""Zerlegt den KEV-Katalog in eine JSON-Datei pro CVE: YYYY/CVE-YYYY-NNNN.json"""
import json
import re
import sys
from pathlib import Path

CVE_RE = re.compile(r"^CVE-(\d{4})-\d{4,}$")

source = Path(sys.argv[1])
catalog = json.loads(source.read_text(encoding="utf-8"))
vulns = catalog.get("vulnerabilities", [])

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
    content = json.dumps(v, indent=2, ensure_ascii=False) + "\n"

    if target.exists():
        if target.read_text(encoding="utf-8") == content:
            unchanged += 1
            continue
        updated += 1
    else:
        new += 1

    target.parent.mkdir(exist_ok=True)
    target.write_text(content, encoding="utf-8")

print(f"Katalog {catalog.get('catalogVersion')}: {new} neu, {updated} geändert, "
      f"{unchanged} unverändert, {skipped} übersprungen")
