#!/usr/bin/env python3
"""Test Module Consolidation Refactoring Assistant.

Helps refactor test modules from multiple test classes to single consolidated class.
Pattern: N test classes → 1 main TestFlextLdif[Module] class with StrEnum + ClassVar + parametrize
"""

from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import NamedTuple


class FileAnalysis(NamedTuple):
    """Analysis result for a test file."""

    file_path: Path
    line_count: int
    class_count: int
    method_count: int
    class_names: list[str]
    method_counts: dict[str, int]


def analyze_test_file(file_path: Path) -> FileAnalysis:
    """Analyze a test file structure."""
    if not file_path.exists():
        msg = f"File not found: {file_path}"
        raise FileNotFoundError(msg)

    with Path(file_path).open("r", encoding="utf-8") as f:
        content = f.read()

    lines = content.split("\n")
    line_count = len(lines)

    # Find all test classes
    class_pattern = r"^class (Test\w+):"
    classes = list(re.finditer(class_pattern, content, re.MULTILINE))
    class_count = len(classes)
    class_names = [match.group(1) for match in classes]

    # Count methods per class
    method_counts = {}
    total_methods = 0

    for i, class_match in enumerate(classes):
        class_name = class_names[i]
        class_start = class_match.start()

        # Find next class or end of file
        class_end = classes[i + 1].start() if i + 1 < len(classes) else len(content)

        class_content = content[class_start:class_end]
        method_count = len(re.findall(r"    def test_", class_content))
        method_counts[class_name] = method_count
        total_methods += method_count

    return FileAnalysis(
        file_path=file_path,
        line_count=line_count,
        class_count=class_count,
        method_count=total_methods,
        class_names=class_names,
        method_counts=method_counts,
    )


def print_analysis(analysis: FileAnalysis) -> None:
    """Print analysis result."""
    print(f"\n📋 Analysis: {analysis.file_path.name}")
    print(f"   Lines: {analysis.line_count}")
    print(f"   Classes: {analysis.class_count}")
    print(f"   Methods: {analysis.method_count}")
    print(
        f"   Estimated reduction (30%): {analysis.file_path.name} → {int(analysis.line_count * 0.7)} lines",
    )
    print("\n   Classes and test counts:")
    for class_name, method_count in analysis.method_counts.items():
        print(f"   - {class_name}: {method_count} tests")


def main() -> None:
    """Main entry point."""
    if len(sys.argv) < 2:
        print("Usage: python refactor_test_consolidation.py <test_file_path>")
        print("\nExample:")
        print(
            "  python refactor_test_consolidation.py tests/unit/quirks/servers/test_apache_quirks.py",
        )
        sys.exit(1)

    file_path = Path(sys.argv[1])

    try:
        analysis = analyze_test_file(file_path)
        print_analysis(analysis)

        print("\n✅ Analysis complete!")
        print("\nNext steps:")
        print("  1. Review class structure above")
        print("  2. Create [file]_new.py with consolidated TestFlextLdif[Module] class")
        print("  3. Use StrEnum for test scenarios")
        print("  4. Parametrize tests with pytest.mark.parametrize")
        print("  5. Validate: ruff check + mypy + pytest --co + pytest")
        print("  6. Swap: old → .bak, new → main")

    except FileNotFoundError as e:
        print(f"❌ Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
