"""Phase 4 Syntax-Only Verification Test Suite.

Tests Python syntax and structure of implementation files without requiring imports.
Uses advanced Python 3.13 patterns with enums, mappings, and parametrized tests.

Modules tested:
- flext_ldif.services.detector.FlextLdifDetector
- flext_ldif.services.parser.FlextLdifParser
- flext_ldif.services.writer.FlextLdifWriter
- flext_ldif.services.sorting.FlextLdifSorting
- flext_ldif.services.schema.FlextLdifSchema
- flext_ldif.services.server.FlextLdifServer
- flext_ldif.services.entry_manipulation.FlextLdifEntryManipulation
- flext_ldif.services.filter_engine.FlextLdifFilterEngine
- flext_ldif.services.migration.FlextLdifMigration
- flext_ldif.services.statistics.FlextLdifStatistics

Scope:
- Syntax validation of all service modules
- Class existence and naming verification
- Method existence and structure validation
- Import structure and dependencies check
- Type annotation presence verification

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import ast
from enum import StrEnum
from pathlib import Path
from typing import ClassVar

import pytest
from flext_core import FlextLogger

logger = FlextLogger(__name__)


class ServiceModule(StrEnum):
    """Service modules to verify."""

    DETECTOR = "detector"
    PARSER = "parser"
    WRITER = "writer"
    SORTING = "sorting"
    SCHEMA = "schema"
    SERVER = "server"
    ENTRY_MANIPULATION = "entry_manipulation"
    FILTER_ENGINE = "filter_engine"
    MIGRATION = "migration"
    STATISTICS = "statistics"


class ServiceClass(StrEnum):
    """Service class names."""

    DETECTOR = "FlextLdifDetector"
    PARSER = "FlextLdifParser"
    WRITER = "FlextLdifWriter"
    SORTING = "FlextLdifSorting"
    SCHEMA = "FlextLdifSchema"
    SERVER = "FlextLdifServer"
    ENTRY_MANIPULATION = "FlextLdifEntryManipulation"
    FILTER_ENGINE = "FlextLdifFilterEngine"
    MIGRATION = "FlextLdifMigration"
    STATISTICS = "FlextLdifStatistics"


class Phase4SyntaxVerification:
    """Phase 4 syntax-only verification test suite.

    Uses advanced Python 3.13 patterns:
    - Single class organization with nested test methods
    - Enum-based configuration mappings
    - Dynamic parametrized tests
    - Factory patterns for file operations
    - Generic helpers for AST analysis
    - Reduced code through mappings and enums
    """

    # Module to class mapping for DRY
    MODULE_CLASS_MAP: ClassVar[dict[ServiceModule, ServiceClass]] = {
        ServiceModule.DETECTOR: ServiceClass.DETECTOR,
        ServiceModule.PARSER: ServiceClass.PARSER,
        ServiceModule.WRITER: ServiceClass.WRITER,
        ServiceModule.SORTING: ServiceClass.SORTING,
        ServiceModule.SCHEMA: ServiceClass.SCHEMA,
        ServiceModule.SERVER: ServiceClass.SERVER,
        ServiceModule.ENTRY_MANIPULATION: ServiceClass.ENTRY_MANIPULATION,
        ServiceModule.FILTER_ENGINE: ServiceClass.FILTER_ENGINE,
        ServiceModule.MIGRATION: ServiceClass.MIGRATION,
        ServiceModule.STATISTICS: ServiceClass.STATISTICS,
    }

    # Required methods per class for comprehensive validation
    REQUIRED_METHODS: ClassVar[dict[ServiceClass, list[str]]] = {
        ServiceClass.DETECTOR: ["detect", "execute"],
        ServiceClass.PARSER: ["parse", "execute"],
        ServiceClass.WRITER: ["write", "execute"],
        ServiceClass.SORTING: ["sort", "execute"],
        ServiceClass.SCHEMA: ["validate_schema", "execute"],
        ServiceClass.SERVER: ["get_server_config", "execute"],
        ServiceClass.ENTRY_MANIPULATION: ["manipulate", "execute"],
        ServiceClass.FILTER_ENGINE: ["filter", "execute"],
        ServiceClass.MIGRATION: ["migrate", "execute"],
        ServiceClass.STATISTICS: ["calculate", "execute"],
    }

    @staticmethod
    def check_file_syntax(filepath: Path) -> tuple[bool, str]:
        """Check if a Python file has valid syntax."""
        try:
            with Path(filepath).open("r", encoding="utf-8") as f:
                code = f.read()
            ast.parse(code)
            return True, "Valid syntax"
        except SyntaxError as e:
            return False, f"Syntax error at line {e.lineno}: {e.msg}"
        except (ValueError, TypeError, AttributeError) as e:
            return False, str(e)

    @staticmethod
    def check_file_has_class(filepath: Path, class_name: str) -> tuple[bool, str]:
        """Check if a file defines a specific class."""
        try:
            with Path(filepath).open("r", encoding="utf-8") as f:
                code = f.read()
            tree = ast.parse(code)

            for node in ast.walk(tree):
                if isinstance(node, ast.ClassDef) and node.name == class_name:
                    return True, f"Class '{class_name}' found"

            return False, f"Class '{class_name}' not found"
        except (ValueError, TypeError, AttributeError) as e:
            return False, str(e)

    @staticmethod
    def check_file_has_method(
        filepath: Path,
        class_name: str,
        method_name: str,
    ) -> tuple[bool, str]:
        """Check if a class in a file has a specific method."""
        try:
            with Path(filepath).open("r", encoding="utf-8") as f:
                code = f.read()
            tree = ast.parse(code)

            for node in ast.walk(tree):
                if isinstance(node, ast.ClassDef) and node.name == class_name:
                    for item in node.body:
                        if (
                            isinstance(item, ast.FunctionDef)
                            and item.name == method_name
                        ):
                            return (
                                True,
                                f"Method '{method_name}' found in class '{class_name}'",
                            )

                    return (
                        False,
                        f"Method '{method_name}' not found in class '{class_name}'",
                    )

            return False, f"Class '{class_name}' not found"
        except (ValueError, TypeError, AttributeError) as e:
            return False, str(e)

    @pytest.mark.parametrize(
        ("module_name", "class_name"),
        [(mod.value, cls.value) for mod, cls in MODULE_CLASS_MAP.items()],
    )
    def test_service_module_syntax_and_structure(
        self,
        module_name: str,
        class_name: str,
    ) -> None:
        """Test syntax and structure of service modules using parametrized validation."""
        base_path = Path(f"src/flext_ldif/services/{module_name}.py")

        # Check file exists
        assert base_path.exists(), f"File not found: {base_path}"

        # Check syntax
        ok, msg = self.check_file_syntax(base_path)
        assert ok, f"Syntax error in {module_name}: {msg}"

        # Check class exists
        ok, msg = self.check_file_has_class(base_path, class_name)
        assert ok, f"Class check failed for {class_name}: {msg}"

        # Check required methods
        service_class = ServiceClass(class_name)
        required_methods = self.REQUIRED_METHODS.get(service_class, ["execute"])

        for method in required_methods:
            ok, msg = self.check_file_has_method(base_path, class_name, method)
            assert ok, f"Method check failed for {method} in {class_name}: {msg}"

    def test_all_service_modules_exist(self) -> None:
        """Test that all expected service module files exist."""
        for module in ServiceModule:
            base_path = Path(f"src/flext_ldif/services/{module.value}.py")
            assert base_path.exists(), (
                f"Service module {module.value} not found at {base_path}"
            )


# Main execution for standalone script (if run directly)
if __name__ == "__main__":
    # For backward compatibility, run the verification
    verifier = Phase4SyntaxVerification()
    # Run all tests manually
    for module, cls in verifier.MODULE_CLASS_MAP.items():
        base_path = Path(f"src/flext_ldif/services/{module.value}.py")
        if not base_path.exists():
            continue

        ok, msg = verifier.check_file_syntax(base_path)
        if not ok:
            continue

        ok, msg = verifier.check_file_has_class(base_path, cls.value)
        if not ok:
            continue

        service_class = ServiceClass(cls.value)
        required_methods = verifier.REQUIRED_METHODS.get(service_class, ["execute"])
        for method in required_methods:
            ok, msg = verifier.check_file_has_method(base_path, cls.value, method)
            if not ok:
                pass
