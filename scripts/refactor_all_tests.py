#!/usr/bin/env python3
"""Automated test refactoring script for flext-ldif.

Consolidates multiple test classes into single TestFlextLdif[Module] classes
using modern patterns (StrEnum, ClassVar, pytest.mark.parametrize).

Usage:
    python scripts/refactor_all_tests.py <test_file_path>
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import TypedDict


class TestFileStats(TypedDict):
    """Statistics for a test file."""

    path: str
    lines: int
    classes: int
    methods: int
    fixtures: int
    class_names: list[str]
    method_names: list[str]
    fixture_names: list[str]


def analyze_test_file(file_path: Path) -> TestFileStats:
    """Analyze test file structure."""
    content = file_path.read_text(encoding='utf-8')

    classes = re.findall(r'^class (Test\w+).*?:', content, re.MULTILINE)
    methods = re.findall(r'^\s{4}def (test_\w+)\(', content, re.MULTILINE)
    fixtures = re.findall(r'@pytest\.fixture.*?\ndef (\w+)\(', content, re.DOTALL)

    return TestFileStats(
        path=str(file_path),
        lines=len(content.split('\n')),
        classes=len(classes),
        methods=len(methods),
        fixtures=len(fixtures),
        class_names=classes,
        method_names=methods,
        fixture_names=fixtures,
    )


def process_test_file(file_path: Path) -> bool:
    """Process a single test file for refactoring."""
    stats = analyze_test_file(file_path)

    print(f"\n{'=' * 80}")
    print(f"📋 ANALYZING: {file_path.name}")
    print(f"{'=' * 80}")
    print(f"Lines: {stats['lines']:,}")
    print(f"Classes: {stats['classes']}")
    print(f"Methods: {stats['methods']}")
    print(f"Fixtures: {stats['fixtures']}")
    print("\nClasses found:")
    for cls in stats['class_names']:
        print(f"  - {cls}")

    if stats['classes'] <= 1:
        print("\n✅ Already consolidated - skipping")
        return False

    print(f"\n⚠️  Needs refactoring: {stats['classes']} → 1 class")
    print(f"📊 Expected savings: ~{int(stats['lines'] * 0.25)}-{int(stats['lines'] * 0.35)} lines (25-35%)")

    return True


def main() -> None:
    """Main entry point."""
    test_dir = Path("/home/marlonsc/flext/flext-ldif/tests")

    # Find all test files
    test_files = sorted(test_dir.rglob("test_*.py"))

    print(f"\n🔍 Found {len(test_files)} test files")

    needs_refactoring = []
    already_done = []

    for test_file in test_files:
        if process_test_file(test_file):
            needs_refactoring.append(test_file)
        else:
            already_done.append(test_file)

    print(f"\n{'=' * 80}")
    print("SUMMARY")
    print(f"{'=' * 80}")
    print(f"✅ Already consolidated: {len(already_done)}")
    print(f"⏳ Need refactoring: {len(needs_refactoring)}")

    if needs_refactoring:
        print("\nFiles to refactor (in priority order):")
        for f in needs_refactoring:
            rel_path = f.relative_to(test_dir.parent)
            print(f"  - {rel_path}")


if __name__ == "__main__":
    main()
