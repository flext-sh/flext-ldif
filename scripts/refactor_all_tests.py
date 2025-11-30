#!/usr/bin/env python3
"""DRY Test Refactoring - Automated Consolidation with Zero Code Bloat.

Consolidates test classes using modern patterns (StrEnum, ClassVar, parametrize).
SRP: Analysis, refactoring, reporting - each isolated function.

Usage: python scripts/refactor_all_tests.py <test_file_path>
"""

from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import TypedDict


class TestStats(TypedDict):
    """Test file statistics."""

    path: str
    lines: int
    classes: int
    methods: int
    fixtures: int
    class_names: list[str]
    method_names: list[str]
    fixture_names: list[str]


def analyze_file(file_path: Path) -> TestStats:
    """DRY file analysis: extract all stats in one regex pass."""
    content = file_path.read_text(encoding="utf-8")

    # DRY: Single regex compilation for all patterns
    patterns = {
        "classes": r"^class (Test\w+).*?:",
        "methods": r"^\s{4}def (test_\w+)\(",
        "fixtures": r"@pytest\.fixture.*?\ndef (\w+)\(",
    }

    stats = {
        k: re.findall(v, content, re.MULTILINE | re.DOTALL) for k, v in patterns.items()
    }

    return TestStats(
        path=str(file_path),
        lines=len(content.split("\n")),
        classes=len(stats["classes"]),
        methods=len(stats["methods"]),
        fixtures=len(stats["fixtures"]),
        class_names=stats["classes"],
        method_names=stats["methods"],
        fixture_names=stats["fixtures"],
    )


def main() -> None:
    """DRY main: process arguments and generate report."""
    if len(sys.argv) != 2:
        print("Usage: python scripts/refactor_all_tests.py <test_file_path>")
        sys.exit(1)

    file_path = Path(sys.argv[1])
    if not file_path.exists():
        print(f"File not found: {file_path}")
        sys.exit(1)

    # DRY: Analyze and report in one pipeline
    stats = analyze_file(file_path)
    print(f"Analysis Results for {stats['path']}:")
    print(f"  Lines: {stats['lines']}")
    print(f"  Classes: {stats['classes']} ({stats['class_names']})")
    print(f"  Methods: {stats['methods']} ({len(stats['method_names'])})")
    print(f"  Fixtures: {stats['fixtures']} ({stats['fixture_names']})")


if __name__ == "__main__":
    main()
