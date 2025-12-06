#!/usr/bin/env python3
"""Comprehensive AST analysis to identify unused code in flext-ldif.

This script analyzes the flext-ldif codebase using AST to find:
- Unused classes (not imported/used via API or DI)
- Unused methods (not called anywhere)
- Unused functions (not called anywhere)

Special handling:
- Server classes are used via DI (auto-discovery in FlextLdifServer)
- Code must be accessible via API (flext_ldif imports)
- Code must be used in flext-ldif, flext-ldap, or client-a-oud-mig

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import ast
import contextlib
from collections import defaultdict
from pathlib import Path

# Project roots
FLEXT_ROOT = Path(__file__).parent.parent.parent
FLEXT_LDIF_ROOT = FLEXT_ROOT / "flext-ldif"
FLEXT_LDAP_ROOT = FLEXT_ROOT / "flext-ldap"
client-a_OUD_MIG_ROOT = FLEXT_ROOT / "client-a-oud-mig"

# Source directories to analyze
FLEXT_LDIF_SRC = FLEXT_LDIF_ROOT / "src" / "flext_ldif"
FLEXT_LDAP_SRC = (
    FLEXT_LDAP_ROOT / "src" / "flext_ldap" if FLEXT_LDAP_ROOT.exists() else None
)
client-a_OUD_MIG_SRC = (
    client-a_OUD_MIG_ROOT / "src" / "client-a_oud_mig"
    if client-a_OUD_MIG_ROOT.exists()
    else None
)

# All source directories
ALL_SRC_DIRS = [
    d for d in [FLEXT_LDIF_SRC, FLEXT_LDAP_SRC, client-a_OUD_MIG_SRC] if d and d.exists()
]

# Test directories
FLEXT_LDIF_TESTS = FLEXT_LDIF_ROOT / "tests"
FLEXT_LDAP_TESTS = FLEXT_LDAP_ROOT / "tests" if FLEXT_LDAP_ROOT.exists() else None
client-a_OUD_MIG_TESTS = (
    client-a_OUD_MIG_ROOT / "tests" if client-a_OUD_MIG_ROOT.exists() else None
)

ALL_TEST_DIRS = [
    d
    for d in [FLEXT_LDIF_TESTS, FLEXT_LDAP_TESTS, client-a_OUD_MIG_TESTS]
    if d and d.exists()
]


class CodeAnalyzer(ast.NodeVisitor):
    """AST visitor to extract code definitions and references."""

    def __init__(self, file_path: Path) -> None:
        """Initialize analyzer for a specific file."""
        self.file_path = file_path
        self.definitions: dict[str, list[tuple[str, int, str]]] = defaultdict(list)
        self.references: set[str] = set()
        self.imports: dict[str, str] = {}  # name -> module
        self.import_froms: dict[str, set[str]] = defaultdict(
            set,
        )  # module -> set of names
        self.current_class: str | None = None
        self.class_stack: list[str | None] = []

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        """Visit class definitions."""
        class_name = node.name
        if self.current_class:
            full_name = f"{self.current_class}.{class_name}"
        else:
            full_name = class_name

        self.definitions["class"].append((full_name, node.lineno, class_name))

        self.class_stack.append(self.current_class)
        self.current_class = full_name
        self.generic_visit(node)
        self.current_class = self.class_stack.pop()

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
            name = alias.asname or alias.name
            self.imports[name] = alias.name
            # Track module imports
            self.import_froms[alias.name].add(name)
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        """Visit from ... import statements."""
        module = node.module or ""
        for alias in node.names:
            name = alias.asname or alias.name
            imported_name = alias.name
            self.imports[name] = (
                f"{module}.{imported_name}" if module else imported_name
            )
            if module:
                self.import_froms[module].add(imported_name)
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
) -> tuple[
    dict[str, list[tuple[str, int, str]]],
    set[str],
    dict[str, str],
    dict[str, set[str]],
]:
    """Analyze a Python file and return definitions, references, imports, and import_froms."""
    try:
        content = file_path.read_text(encoding="utf-8")
        tree = ast.parse(content, filename=str(file_path))
        analyzer = CodeAnalyzer(file_path)
        analyzer.visit(tree)
        return (
            analyzer.definitions,
            analyzer.references,
            analyzer.imports,
            analyzer.import_froms,
        )
    except Exception:
        return {}, set(), {}, {}


def find_all_python_files(root: Path) -> list[Path]:
    """Find all Python files in a directory."""
    if not root.exists():
        return []
    return [f for f in root.rglob("*.py") if "__pycache__" not in str(f)]


def collect_all_definitions() -> dict[str, dict[str, tuple[Path, int, str]]]:
    """Collect all definitions from flext-ldif source files only."""
    all_defs: dict[str, dict[str, tuple[Path, int, str]]] = {
        "class": {},
        "method": {},
        "function": {},
    }

    for py_file in find_all_python_files(FLEXT_LDIF_SRC):
        defs, _, _, _ = analyze_file(py_file)
        for def_type in ["class", "method", "function"]:
            for full_name, lineno, short_name in defs.get(def_type, []):
                if full_name not in all_defs[def_type]:
                    all_defs[def_type][full_name] = (py_file, lineno, short_name)

    return all_defs


def collect_all_references_and_imports() -> tuple[set[str], dict[str, set[str]]]:
    """Collect all references and imports from all projects."""
    all_refs: set[str] = set()
    all_import_froms: dict[str, set[str]] = defaultdict(set)

    # Analyze all source and test files
    for src_dir in ALL_SRC_DIRS + ALL_TEST_DIRS:
        for py_file in find_all_python_files(src_dir):
            _, refs, imports, import_froms = analyze_file(py_file)
            all_refs.update(refs)
            all_refs.update(imports.keys())
            for module, names in import_froms.items():
                all_import_froms[module].update(names)

    return all_refs, all_import_froms


def check_server_class_usage(
    class_name: str,
    all_import_froms: dict[str, set[str]],
) -> bool:
    """Check if a server class is used via DI or API."""
    # Check if it's imported from flext_ldif.servers
    if "flext_ldif.servers" in all_import_froms:
        short_name = class_name.rsplit(".", maxsplit=1)[-1]
        if short_name in all_import_froms["flext_ldif.servers"]:
            return True

    # Check if it's in __init__.py exports
    init_file = FLEXT_LDIF_SRC / "servers" / "__init__.py"
    if init_file.exists():
        init_content = init_file.read_text(encoding="utf-8")
        short_name = class_name.rsplit(".", maxsplit=1)[-1]
        if short_name in init_content:
            return True

    # Server classes are auto-discovered via inspect.getmembers
    # So if they extend FlextLdifServersBase and are in servers package, they're used
    return False


def check_api_usage(
    def_name: str,
    all_refs: set[str],
    all_import_froms: dict[str, set[str]],
) -> bool:
    """Check if a definition is used via API imports or direct references."""
    # Check direct reference
    if def_name in all_refs:
        return True

    # Check if it's imported and used
    parts = def_name.split(".")
    for i in range(len(parts)):
        partial = ".".join(parts[i:])
        if partial in all_refs:
            return True

    # Check class name without module
    if "." in def_name:
        class_name = def_name.rsplit(".", maxsplit=1)[-1]
        if class_name in all_refs:
            return True

    # Check imports from flext_ldif
    if "flext_ldif" in all_import_froms:
        short_name = def_name.rsplit(".", maxsplit=1)[-1]
        if short_name in all_import_froms["flext_ldif"]:
            return True

    return False


def _collect_server_classes_v2() -> set[str]:
    """Collect server class names from server/*.py files."""
    server_files = list((FLEXT_LDIF_SRC / "servers").glob("*.py"))
    server_classes: set[str] = set()
    for server_file in server_files:
        if server_file.name in {"__init__.py", "base.py"}:
            continue
        defs, _, _, _ = analyze_file(server_file)
        server_classes.update(full_name for full_name, _, _ in defs.get("class", []))
    return server_classes


def _is_private_method_used(
    def_type: str,
    full_name: str,
    short_name: str,
    all_refs: list[str],
) -> bool:
    """Check if private method is used within its class."""
    if def_type != "method":
        return False

    # Check if called within the same class
    class_name = ".".join(full_name.split(".")[:-1])
    return bool(class_name and f"{class_name}.{short_name}" in all_refs)


def _check_unused_definition_v2(
    def_type: str,
    full_name: str,
    file_path: Path,
    lineno: int,
    server_classes: set[str],
    all_refs: list[str],
    all_import_froms: dict[str, set[str]],
) -> tuple[str, Path, int] | None:
    """Check if a definition is unused. Returns tuple if unused, None otherwise."""
    # Check usage based on type
    if def_type == "class" and full_name in server_classes:
        is_used = check_server_class_usage(full_name, all_import_froms)
    else:
        is_used = check_api_usage(full_name, all_refs, all_import_froms)

    if is_used:
        return None

    # Handle private vs public code
    short_name = full_name.rsplit(".", maxsplit=1)[-1]
    if short_name.startswith("_"):
        # Private code - check if actually referenced
        if full_name in all_refs or short_name in all_refs:
            return None

        # For methods, check if called within class
        if _is_private_method_used(def_type, full_name, short_name, all_refs):
            return None

        return (full_name, file_path, lineno)

    # Public code - must be used
    return (full_name, file_path, lineno)


def find_unused_code() -> dict[str, list[tuple[str, Path, int]]]:
    """Find unused code across all projects."""
    all_defs = collect_all_definitions()
    all_refs, all_import_froms = collect_all_references_and_imports()
    server_classes = _collect_server_classes_v2()

    unused: dict[str, list[tuple[str, Path, int]]] = {
        "class": [],
        "method": [],
        "function": [],
    }

    # Check each definition
    for def_type in ["class", "method", "function"]:
        for full_name, (file_path, lineno, _) in all_defs[def_type].items():
            unused_item = _check_unused_definition_v2(
                def_type,
                full_name,
                file_path,
                lineno,
                server_classes,
                all_refs,
                all_import_froms,
            )
            if unused_item:
                unused[def_type].append(unused_item)

    return unused


def main() -> None:
    """Main entry point."""
    unused = find_unused_code()

    total_unused = 0
    for def_type in ["class", "method", "function"]:
        items = unused[def_type]
        total_unused += len(items)
        if items:
            for _name, file_path, _lineno in sorted(
                items,
                key=lambda x: (str(x[1]), x[2]),
            ):
                with contextlib.suppress(ValueError):
                    file_path.relative_to(FLEXT_LDIF_ROOT)


if __name__ == "__main__":
    main()
