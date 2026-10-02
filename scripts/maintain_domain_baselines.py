#!/usr/bin/env python3
"""Build the repository-owned AI and non-CN domain baselines.

The input is a privacy-safe export containing only lines in the form
``id=<group> dns=<domain-or-pattern>``.  No Panabit configuration or
credentials are needed.  AI owns exact duplicates and subdomains so that the
same service is not present in both lists.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


AI_GROUP = 4
NON_CN_GROUP = 2
DEFAULT_AI_ADDITIONS = ("api.openai.com",)


def canonical(value: str) -> str:
    return value.strip().lower().rstrip(".")


def parse_export(path: Path) -> dict[int, list[str]]:
    groups: dict[int, list[str]] = {AI_GROUP: [], NON_CN_GROUP: []}
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or not line.startswith("id="):
            continue
        try:
            group_text, value = line.split(" dns=", 1)
            group_id = int(group_text.removeprefix("id="))
        except ValueError as exc:
            raise ValueError(f"invalid export line: {raw_line!r}") from exc
        if group_id in groups and value.strip():
            groups[group_id].append(value.strip())
    missing = [str(group_id) for group_id, values in groups.items() if not values]
    if missing:
        raise ValueError("export is missing required group(s): " + ", ".join(missing))
    return groups


def unique_sorted(values: list[str]) -> list[str]:
    by_key: dict[str, str] = {}
    for value in values:
        key = canonical(value)
        by_key.setdefault(key, value.strip())
    return sorted(by_key.values(), key=canonical)


def covered_by_ai(value: str, ai_domains: set[str]) -> tuple[str, str] | None:
    """Return (owner, reason) only for literal domain entries.

    Panabit's ``^`` entries are patterns rather than suffixes.  They are kept
    in their source group unless the pattern itself is an exact duplicate.
    """

    value_key = canonical(value)
    if value_key in ai_domains:
        return value_key, "exact"
    if value_key.startswith("^"):
        return None
    # Prefer the most specific suffix and keep output stable across Python
    # hash seeds (set iteration order is intentionally not deterministic).
    for owner in sorted(ai_domains, key=lambda item: (-len(item), item)):
        if owner.startswith("^"):
            continue
        if value_key.endswith("." + owner):
            return owner, "ai_suffix"
    return None


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_lines(path: Path, values: list[str]) -> None:
    path.write_text("".join(f"{value}\n" for value in values), encoding="utf-8")


def build(input_path: Path, out_dir: Path, additions: tuple[str, ...]) -> None:
    groups = parse_export(input_path)
    ai = unique_sorted(groups[AI_GROUP] + list(additions))
    ai_keys = {canonical(value) for value in ai}

    non_cn: list[str] = []
    removed: list[tuple[str, str, str]] = []
    for value in unique_sorted(groups[NON_CN_GROUP]):
        covered = covered_by_ai(value, ai_keys)
        if covered is None:
            non_cn.append(value)
        else:
            owner, reason = covered
            removed.append((value, owner, reason))

    out_dir.mkdir(parents=True, exist_ok=True)
    ai_path = out_dir / "ai.txt"
    non_cn_path = out_dir / "non-cn.txt"
    overlap_path = out_dir / "overlap.tsv"
    write_lines(ai_path, ai)
    write_lines(non_cn_path, non_cn)
    overlap_lines = ["# non-cn entry\tAI owner\treason\n"]
    overlap_lines.extend(f"{value}\t{owner}\t{reason}\n" for value, owner, reason in removed)
    overlap_path.write_text("".join(overlap_lines), encoding="utf-8")

    manifest = {
        "schema_version": 1,
        "source": {
            "ai_group": "Panabit dnsgrp id=4 (AI)",
            "non_cn_group": "Panabit dnsgrp id=2 (!CN)",
            "input_format": "id=<group> dns=<domain-or-pattern>",
        },
        "policy": {
            "owner_precedence": "ai",
            "dedupe": "case-insensitive exact entries and literal subdomains covered by an AI suffix",
            "patterns": "entries beginning with ^ are preserved and only exact-deduped",
        },
        "counts": {
            "ai_imported": len(unique_sorted(groups[AI_GROUP])),
            "ai_managed_additions": len(additions),
            "ai_total": len(ai),
            "non_cn_imported": len(unique_sorted(groups[NON_CN_GROUP])),
            "non_cn_total": len(non_cn),
            "removed_from_non_cn": len(removed),
        },
        "managed_additions": list(additions),
        "files": {
            "ai.txt": {"entries": len(ai), "sha256": sha256(ai_path)},
            "non-cn.txt": {"entries": len(non_cn), "sha256": sha256(non_cn_path)},
            "overlap.tsv": {"entries": len(removed), "sha256": sha256(overlap_path)},
        },
    }
    (out_dir / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path, help="privacy-safe Panabit domain export")
    parser.add_argument("--out-dir", type=Path, default=Path("domains"))
    parser.add_argument(
        "--ai-addition",
        action="append",
        dest="additions",
        help="literal AI domain to keep in the repository baseline",
    )
    args = parser.parse_args()
    additions = tuple(args.additions) if args.additions else DEFAULT_AI_ADDITIONS
    build(args.input, args.out_dir, additions)


if __name__ == "__main__":
    main()
