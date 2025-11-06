#!/usr/bin/env python3
"""AST-based unused code analyzer for flext-ldif.

Identifies modules, classes, functions, and methods that are defined but never used.
Generates a comprehensive report for manual review and removal.

Usage:
    python scripts/analyze_unused_code.py
    python scripts/analyze_unused_code.py --output report.json
    python scripts/analyze_unused_code.py --verbose
"""

from __future__ import annotations

import argparse
import ast
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class CodeDefinition:
    """Represents a code definition (class, function, method, etc.)."""

    name: str
    kind: str  # 'class', 'function', 'method', 'module'
    file_path: str
    line_number: int
    references: set[str] = field(default_factory=set)
    is_public: bool = True  # Does NOT start with _
    is_used: bool = False

    def __hash__(self) -> int:
        """Make hashable by combining name and file path."""
        return hash((self.name, self.file_path))

    def __eq__(self, other: object) -> bool:
        """Compare by name and file path."""
        if not isinstance(other, CodeDefinition):
            return False
        return self.name == other.name and self.file_path == other.file_path


@dataclass
class UnusedCodeReport:
    """Report of unused code findings."""

    unused_modules: list[str] = field(default_factory=list)
    unused_functions: list[CodeDefinition] = field(default_factory=list)
    unused_classes: list[CodeDefinition] = field(default_factory=list)
    unused_methods: list[CodeDefinition] = field(default_factory=list)
    unused_module_functions: list[CodeDefinition] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert report to dictionary for JSON serialization."""
        return {
            "unused_modules": self.unused_modules,
            "unused_functions": [
                {
                    "name": f.name,
                    "file": f.file_path,
                    "line": f.line_number,
                    "kind": f.kind,
                }
                for f in self.unused_functions
            ],
            "unused_classes": [
                {
                    "name": c.name,
                    "file": c.file_path,
                    "line": c.line_number,
                    "kind": c.kind,
                }
                for c in self.unused_classes
            ],
            "unused_methods": [
                {
                    "name": m.name,
                    "file": m.file_path,
                    "line": m.line_number,
                    "parent_class": m.kind,
                }
                for m in self.unused_methods
            ],
            "unused_module_functions": [
                {
                    "name": f.name,
                    "file": f.file_path,
                    "line": f.line_number,
                    "kind": f.kind,
                }
                for f in self.unused_module_functions
            ],
        }


class UnusedCodeAnalyzer(ast.NodeVisitor):
    """AST analyzer to find unused code definitions."""

    def __init__(self, file_path: str) -> None:
        """Initialize analyzer with file path."""
        self.file_path = file_path
        self.definitions: dict[str, CodeDefinition] = {}
        self.references: set[str] = set()
        self.current_class: str | None = None

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        """Visit class definitions."""
        is_public = not node.name.startswith("_")

        self.definitions[node.name] = CodeDefinition(
            name=node.name,
            kind="class",
            file_path=self.file_path,
            line_number=node.lineno,
            is_public=is_public,
        )

        # Visit class body to find methods
        old_class = self.current_class
        self.current_class = node.name
        self.generic_visit(node)
        self.current_class = old_class

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        """Visit function and method definitions."""
        is_public = not node.name.startswith("_")

        # Check if this is a method (inside a class)
        if self.current_class:
            method_name = f"{self.current_class}.{node.name}"
            kind = "method"
        else:
            method_name = node.name
            kind = "function"

        self.definitions[method_name] = CodeDefinition(
            name=node.name,
            kind=kind,
            file_path=self.file_path,
            line_number=node.lineno,
            is_public=is_public,
        )

        self.generic_visit(node)

    def visit_Name(self, node: ast.Name) -> None:
        """Visit name references."""
        self.references.add(node.id)
        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute) -> None:
        """Visit attribute references."""
        self.references.add(node.attr)
        self.generic_visit(node)


def analyze_file(file_path: Path) -> tuple[dict[str, CodeDefinition], set[str]]:
    """Analyze a single Python file for definitions and references."""
    try:
        content = file_path.read_text(encoding="utf-8")
        tree = ast.parse(content, filename=str(file_path))

        analyzer = UnusedCodeAnalyzer(str(file_path))
        analyzer.visit(tree)

        return analyzer.definitions, analyzer.references
    except (SyntaxError, UnicodeDecodeError) as e:
        print(f"Warning: Could not parse {file_path}: {e}", file=sys.stderr)
        return {}, set()


def analyze_codebase(src_dir: Path) -> tuple[dict[str, CodeDefinition], set[str]]:
    """Analyze entire codebase for definitions and references."""
    all_definitions: dict[str, CodeDefinition] = {}
    all_references: set[str] = set()

    # Find all Python files in src/
    for py_file in sorted(src_dir.rglob("*.py")):
        if "__pycache__" in py_file.parts:
            continue

        definitions, references = analyze_file(py_file)
        all_definitions.update(definitions)
        all_references.update(references)

    return all_definitions, all_references


def identify_unused(
    definitions: dict[str, CodeDefinition],
    references: set[str],
) -> UnusedCodeReport:
    """Identify unused definitions based on references."""
    report = UnusedCodeReport()

    # Magic methods and special methods that should not be marked as unused
    magic_methods = {
        "__init__",
        "__str__",
        "__repr__",
        "__eq__",
        "__hash__",
        "__lt__",
        "__le__",
        "__gt__",
        "__ge__",
        "__ne__",
        "__contains__",
        "__len__",
        "__getitem__",
        "__setitem__",
        "__delitem__",
        "__iter__",
        "__next__",
        "__call__",
        "__enter__",
        "__exit__",
        "__await__",
        "__aiter__",
        "__anext__",
        "__aenter__",
        "__aexit__",
    }

    # Common entry points and exports
    common_entry_points = {
        "main",
        "__main__",
        "__all__",
        "create",
        "execute",
        "run",
        "handle",
        "process",
        "parse",
        "build",
        "validate",
        "check",
    }

    for def_name, definition in definitions.items():
        # Skip internal/private definitions
        if not definition.is_public:
            continue

        # Skip magic methods
        if definition.name in magic_methods:
            continue

        # Skip common entry points
        if definition.name in common_entry_points:
            continue

        # Check if definition is referenced anywhere
        base_name = definition.name.split(".")[-1]  # For methods, get method name only
        is_referenced = (
            base_name in references
            or definition.name in references
            or def_name in references
        )

        if not is_referenced:
            definition.is_used = False

            # Categorize unused definition
            if definition.kind == "class":
                report.unused_classes.append(definition)
            elif definition.kind == "method":
                report.unused_methods.append(definition)
            elif definition.kind == "function":
                report.unused_functions.append(definition)

    # Sort by file and line number for readability
    report.unused_classes.sort(key=lambda x: (x.file_path, x.line_number))
    report.unused_functions.sort(key=lambda x: (x.file_path, x.line_number))
    report.unused_methods.sort(key=lambda x: (x.file_path, x.line_number))

    return report


def print_report(report: UnusedCodeReport) -> None:
    """Print analysis report to console."""
    print("\n" + "=" * 80)
    print("FLEXT-LDIF DEAD CODE ANALYSIS REPORT")
    print("=" * 80)

    print("\n📊 SUMMARY:")
    print(f"  Unused Classes:          {len(report.unused_classes)}")
    print(f"  Unused Functions:        {len(report.unused_functions)}")
    print(f"  Unused Methods:          {len(report.unused_methods)}")
    print(
        f"  Total Unused:            {len(report.unused_classes) + len(report.unused_functions) + len(report.unused_methods)}",
    )

    if report.unused_classes:
        print(f"\n🗑️  UNUSED CLASSES ({len(report.unused_classes)}):")
        for cls in report.unused_classes:
            print(f"  {cls.name:40} {cls.file_path}:{cls.line_number}")

    if report.unused_functions:
        print(f"\n🗑️  UNUSED FUNCTIONS ({len(report.unused_functions)}):")
        for func in report.unused_functions:
            print(f"  {func.name:40} {func.file_path}:{func.line_number}")

    if report.unused_methods:
        print(f"\n🗑️  UNUSED METHODS ({len(report.unused_methods)}):")
        for method in sorted(
            report.unused_methods,
            key=lambda m: (m.file_path, m.name),
        ):
            print(f"  {method.name:40} {method.file_path}:{method.line_number}")

    print("\n" + "=" * 80)
    print("NOTE: This analysis uses basic heuristics and may have false positives.")
    print("Always verify before removing code, especially:")
    print("  - Entry points (main, execute, create, etc.)")
    print("  - API exports and public interfaces")
    print("  - Methods called via reflection or decorators")
    print("  - Code imported by external projects (algar-oud-mig, etc.)")
    print("=" * 80 + "\n")


def main() -> None:
    """Main entry point for analyzer."""
    parser = argparse.ArgumentParser(
        description="Analyze flext-ldif codebase for unused code",
    )
    parser.add_argument(
        "--output",
        type=str,
        help="Output JSON report to file",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Print verbose output",
    )
    parser.add_argument(
        "--src-dir",
        type=str,
        default="src",
        help="Source directory to analyze (default: src)",
    )

    args = parser.parse_args()

    src_dir = Path(args.src_dir)
    if not src_dir.exists():
        print(f"Error: Source directory {src_dir} does not exist", file=sys.stderr)
        sys.exit(1)

    print(f"Analyzing {src_dir} for unused code...")

    # Analyze codebase
    definitions, references = analyze_codebase(src_dir)
    print(f"Found {len(definitions)} definitions and {len(references)} references")

    # Identify unused code
    report = identify_unused(definitions, references)

    # Print report
    print_report(report)

    # Output JSON if requested
    if args.output:
        output_path = Path(args.output)
        output_path.write_text(json.dumps(report.to_dict(), indent=2), encoding="utf-8")
        print(f"JSON report written to {output_path}")


if __name__ == "__main__":
    main()
