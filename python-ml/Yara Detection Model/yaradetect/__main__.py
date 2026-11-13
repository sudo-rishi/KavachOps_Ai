from __future__ import annotations

import argparse
import json
from pathlib import Path

try:
    from .core import load_rules_from_dir, load_rules_from_file, scan_dir, scan_file
except ImportError:
    from core import load_rules_from_dir, load_rules_from_file, scan_dir, scan_file


def main() -> None:
    ap = argparse.ArgumentParser(prog="yaradetect", description="Offline pure-Python YARA-ish scanner (approx conditions).")
    ap.add_argument("--rules", required=True, help="Rules path (.yar/.yara file or directory)")
    ap.add_argument("--file", default=None, help="File to scan")
    ap.add_argument("--dir", default=None, help="Directory to scan recursively")
    ap.add_argument("--json", action="store_true", help="Print JSON output")
    ap.add_argument("--output", default=None, help="Write JSON output to this file")
    ap.add_argument("--max-bytes", type=int, default=25_000_000, help="Max bytes to read per file")
    args = ap.parse_args()

    rules_path = Path(args.rules)
    if rules_path.is_dir():
        rules = load_rules_from_dir(rules_path)
    else:
        rules = load_rules_from_file(rules_path)

    if not rules:
        raise SystemExit("No rules loaded. Check --rules path.")

    if not args.file and not args.dir:
        raise SystemExit("Provide --file or --dir")

    if args.file:
        out = scan_file(rules, args.file, max_bytes=args.max_bytes)
    else:
        out = scan_dir(rules, args.dir, max_bytes=args.max_bytes)

    if args.json:
        s = json.dumps(out, indent=2)
        if args.output:
            Path(args.output).write_text(s, encoding="utf-8")
        else:
            print(s)
    else:
        # human output
        if isinstance(out, dict):
            print(f"File: {out['path']}")
            matched = out["matched_rules"]
            if matched:
                print(f"  Matched: {len(matched)} rule(s)")
                for rule_name in matched:
                    print(f"    - {rule_name}")
            else:
                print("  Clean")
        elif isinstance(out, list):
            infected_files = [r for r in out if r["matched_rules"]]
            print(f"Scanned {len(out)} file(s), {len(infected_files)} matched rule(s)")
            for result in infected_files:
                m = result.get("matched_rules", [])
                if m:
                    print(f"  {result['path']}: {', '.join(m)}")


if __name__ == "__main__":
    main()
