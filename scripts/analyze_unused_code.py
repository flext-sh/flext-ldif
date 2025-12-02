#!/usr/bin/env python3
"""AST analysis script to identify unused code in flext-ldif.

This script analyzes the flext-ldif codebase using AST to find:
- Unused classes
- Unused methods
- Unused functions
- Code not referenced by flext-ldif, flext-ldap, or client-a-oud-mig

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import ast
from collections import defaultdict
from pathlib import Path

# Project roots
FLEXT_LDIF_ROOT = Path(__file__).parent.parent
FLEXT_LDAP_ROOT = FLEXT_LDIF_ROOT.parent / "flext-ldap"
client-a_OUD_MIG_ROOT = FLEXT_LDIF_ROOT.parent / "client-a-oud-mig"

# Directories to analyze
_src_dirs_candidates: list[Path | None] = [
    FLEXT_LDIF_ROOT / "src" / "flext_ldif",
    FLEXT_LDAP_ROOT / "src" / "flext_ldap" if FLEXT_LDAP_ROOT.exists() else None,
    client-a_OUD_MIG_ROOT / "src" / "client-a_oud_mig"
    if client-a_OUD_MIG_ROOT.exists()
    else None,
]
SRC_DIRS: list[Path] = [d for d in _src_dirs_candidates if d is not None and d.exists()]


class CodeAnalyzer(ast.NodeVisitor):
    """AST visitor to extract code definitions and references."""

    def __init__(self, file_path: Path) -> None:
        """Initialize analyzer for a specific file."""
        self.file_path = file_path
        self.definitions: dict[str, list[tuple[str, int, str]]] = defaultdict(list)
        self.references: set[str] = set()
        self.current_class: str | None = None
        self.imports: dict[str, str] = {}  # name -> module

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        """Visit class definitions."""
        class_name = node.name
        full_name = (
            f"{self.current_class}.{class_name}" if self.current_class else class_name
        )
        self.definitions["class"].append((full_name, node.lineno, class_name))

        old_class = self.current_class
        self.current_class = full_name
        self.generic_visit(node)
        self.current_class = old_class

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        """Visit function/method definitions."""
        func_name = node.name
        if self.current_class:
            full_name = f"{self.current_class}.{func_name}"
            self.definitions["method"].append((full_name, node.lineno, func_name))
        else:
            self.definitions["function"].append((func_name, node.lineno, func_name))
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        """Visit async function/method definitions."""
        func_name = node.name
        if self.current_class:
            full_name = f"{self.current_class}.{func_name}"
            self.definitions["method"].append((full_name, node.lineno, func_name))
        else:
            self.definitions["function"].append((func_name, node.lineno, func_name))
        self.generic_visit(node)

    def visit_Import(self, node: ast.Import) -> None:
        """Visit import statements."""
        for alias in node.names:
            self.imports[alias.asname or alias.name] = alias.name
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        """Visit from ... import statements."""
        module = node.module or ""
        for alias in node.names:
            name = alias.asname or alias.name
            self.imports[name] = f"{module}.{alias.name}" if module else alias.name
        self.generic_visit(node)

    def visit_Name(self, node: ast.Name) -> None:
        """Visit name references."""
        if isinstance(node.ctx, ast.Load):
            self.references.add(node.id)
        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute) -> None:
        """Visit attribute references."""
        if isinstance(node.ctx, ast.Load):
            # Build full attribute path
            parts: list[str] = []
            current: ast.expr = node
            while isinstance(current, ast.Attribute):
                parts.append(current.attr)
                current = current.value
            if isinstance(current, ast.Name):
                parts.append(current.id)
                full_path = ".".join(reversed(parts))
                self.references.add(full_path)
        self.generic_visit(node)


def analyze_file(
    file_path: Path,
) -> tuple[dict[str, list[tuple[str, int, str]]], set[str], dict[str, str]]:
    """Analyze a Python file and return definitions, references, and imports."""
    try:
        content = file_path.read_text(encoding="utf-8")
        tree = ast.parse(content, filename=str(file_path))
        analyzer = CodeAnalyzer(file_path)
        analyzer.visit(tree)
        return analyzer.definitions, analyzer.references, analyzer.imports
    except Exception as e:
        print(f"Error analyzing {file_path}: {e}")
        return {}, set(), {}


def find_all_python_files(root: Path) -> list[Path]:
    """Find all Python files in a directory."""
    if not root.exists():
        return []
    return list(root.rglob("*.py"))


def collect_all_definitions() -> dict[str, dict[str, tuple[Path, int, str]]]:
    """Collect all definitions from all source files."""
    all_defs: dict[str, dict[str, tuple[Path, int, str]]] = {
        "class": {},
        "method": {},
        "function": {},
    }

    for src_dir in SRC_DIRS:
        for py_file in find_all_python_files(src_dir):
            if "test" in str(py_file) or "__pycache__" in str(py_file):
                continue
            defs, _, _ = analyze_file(py_file)
            for def_type in ["class", "method", "function"]:
                for full_name, lineno, short_name in defs.get(def_type, []):
                    if full_name not in all_defs[def_type]:
                        all_defs[def_type][full_name] = (py_file, lineno, short_name)

    return all_defs


def collect_all_references() -> set[str]:
    """Collect all references from all source files."""
    all_refs: set[str] = set()

    for src_dir in SRC_DIRS:
        for py_file in find_all_python_files(src_dir):
            if "__pycache__" in str(py_file):
                continue
            _, refs, imports = analyze_file(py_file)
            all_refs.update(refs)
            all_refs.update(imports.keys())

    return all_refs


def check_api_usage(def_name: str, all_refs: set[str], imports: dict[str, str]) -> bool:
    """Check if a definition is used via API imports."""
    # Check direct reference
    if def_name in all_refs:
        return True

    # Check if it's imported and used
    parts = def_name.split(".")
    for i in range(len(parts)):
        partial = ".".join(parts[i:])
        if partial in all_refs or partial in imports:
            return True

    # Check class name without module
    if "." in def_name:
        class_name = def_name.rsplit(".", maxsplit=1)[-1]
        if class_name in all_refs:
            return True

    return False


def find_unused_code() -> dict[str, list[tuple[str, Path, int]]]:  # noqa: C901
    """Find unused code across all projects."""
    print("Collecting definitions...")
    all_defs = collect_all_definitions()

    print("Collecting references...")
    all_refs = collect_all_references()

    print("Analyzing usage...")
    unused: dict[str, list[tuple[str, Path, int]]] = {
        "class": [],
        "method": [],
        "function": [],
    }

    # Special handling for server/*.py files - they use DI
    server_files = list(
        (FLEXT_LDIF_ROOT / "src" / "flext_ldif" / "servers").glob("*.py"),
    )
    server_classes: set[str] = set()
    for server_file in server_files:
        if server_file.name in {"__init__.py", "base.py"}:
            continue
        defs, _, _ = analyze_file(server_file)
        server_classes.update(full_name for full_name, _, _ in defs.get("class", []))

    # Check each definition
    for def_type in ["class", "method", "function"]:
        for full_name, (file_path, lineno, _) in all_defs[def_type].items():
            # Skip if it's a server class (DI handles these)
            if def_type == "class" and full_name in server_classes:
                # Check if server class is imported/used
                is_used = False
                for ref in all_refs:
                    if full_name in ref or ref in full_name:
                        is_used = True
                        break
                if not is_used:
                    # Check if it's in __init__.py exports
                    init_file = file_path.parent / "__init__.py"
                    if init_file.exists():
                        init_content = init_file.read_text(encoding="utf-8")
                        if full_name.split(".")[-1] in init_content:
                            is_used = True
                if not is_used:
                    unused[def_type].append((full_name, file_path, lineno))
            # Regular check
            elif not check_api_usage(full_name, all_refs, {}):
                # Check if it's a private method/function (starts with _)
                if not full_name.split(".")[-1].startswith("_"):
                    unused[def_type].append((full_name, file_path, lineno))

    return unused


def main() -> None:
    """Main entry point."""
    print("Starting AST analysis for unused code...")
    print(f"Analyzing: {FLEXT_LDIF_ROOT}")

    unused = find_unused_code()

    print("\n" + "=" * 80)
    print("UNUSED CODE REPORT")
    print("=" * 80)

    for def_type in ["class", "method", "function"]:
        items = unused[def_type]
        if items:
            print(f"\n{def_type.upper()}S ({len(items)}):")
            for name, file_path, lineno in sorted(
                items,
                key=lambda x: (str(x[1]), x[2]),
            ):
                try:
                    rel_path = file_path.relative_to(FLEXT_LDIF_ROOT)
                except ValueError:
                    rel_path = file_path
                print(f"  {name} - {rel_path}:{lineno}")
        else:
            print(f"\n{def_type.upper()}S: None found")

    print("\n" + "=" * 80)


if __name__ == "__main__":
    main()
