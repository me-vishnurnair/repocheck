"""python -m app.cli /path/to/repository --format json"""

import argparse
import json
from pathlib import Path
from .scanner import scan, from_directory


def main():
    parser = argparse.ArgumentParser(
        description="Inspect repository hygiene without executing code."
    )
    parser.add_argument("directory", type=Path)
    parser.add_argument("--format", choices=["text", "json"], default="text")
    parser.add_argument(
        "--fail-on", choices=["high", "medium", "low", "never"], default="high"
    )
    args = parser.parse_args()
    try:
        result = scan(from_directory(args.directory))
    except (ValueError, OSError) as exc:
        parser.error(str(exc))
    if args.format == "json":
        print(json.dumps(result, indent=2))
    else:
        print(f"RepoCheck | {result['files_scanned']} files")
        for f in result["findings"]:
            print(
                f"{f['severity'].upper():6} {f['rule']} {f['path']}:{f['line']} - {f['message']}"
            )
        print(result["notice"])
    levels = ["high", "medium", "low"]
    fail_levels = (
        levels[: levels.index(args.fail_on) + 1] if args.fail_on != "never" else []
    )
    return int(any(result["counts"][level] for level in fail_levels))


if __name__ == "__main__":
    raise SystemExit(main())
