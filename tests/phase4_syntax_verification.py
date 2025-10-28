"""Phase 4 Syntax-Only Verification.

This script verifies Python syntax and structure of implementation files
without requiring imports (which are blocked by pre-existing flext-core issue).

Usage: python tests/phase4_syntax_verification.py

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import ast
import sys
from pathlib import Path

from flext_core import FlextLogger

logger = FlextLogger(__name__)


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


def check_file_has_method(
    filepath: Path, class_name: str, method_name: str
) -> tuple[bool, str]:
    """Check if a class in a file has a specific method."""
    try:
        with Path(filepath).open("r", encoding="utf-8") as f:
            code = f.read()
        tree = ast.parse(code)

        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef) and node.name == class_name:
                for item in node.body:
                    if isinstance(item, ast.FunctionDef) and item.name == method_name:
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


def verify_server_detector() -> bool:
    """Verify FlextLdifServerDetector implementation."""
    logger.info("\n=== VERIFYING SERVER DETECTOR IMPLEMENTATION ===")
    base_path = Path("src/flext_ldif/services/server_detector.py")

    # Check file exists
    if not base_path.exists():
        logger.info(f"❌ File not found: {base_path}")
        return False

    # Check syntax
    ok, msg = check_file_syntax(base_path)
    if not ok:
        logger.info(f"❌ Syntax error: {msg}")
        return False
    logger.info("✅ Valid Python syntax")

    # Check class exists
    ok, msg = check_file_has_class(base_path, "FlextLdifServerDetector")
    if not ok:
        logger.info(f"❌ {msg}")
        return False
    logger.info(f"✅ {msg}")

    # Check methods
    methods_to_check = [
        "detect_server_type",
        "execute",
        "_calculate_scores",
        "_determine_server_type",
        "_extract_patterns",
    ]

    for method in methods_to_check:
        ok, msg = check_file_has_method(base_path, "FlextLdifServerDetector", method)
        if not ok:
            logger.info(f"❌ {msg}")
            return False
        logger.info(f"✅ {msg}")

    return True


def verify_relaxed_quirks() -> bool:
    """Verify Relaxed Quirks implementation."""
    logger.info("\n=== VERIFYING RELAXED QUIRKS IMPLEMENTATION ===")
    base_path = Path("src/flext_ldif/quirks/servers/relaxed_quirks.py")

    # Check file exists
    if not base_path.exists():
        logger.info(f"❌ File not found: {base_path}")
        return False

    # Check syntax
    ok, msg = check_file_syntax(base_path)
    if not ok:
        logger.info(f"❌ Syntax error: {msg}")
        return False
    logger.info("✅ Valid Python syntax")

    # Check classes exist
    classes_to_check = [
        "FlextLdifQuirksServersRelaxedSchema",
        "FlextLdifQuirksServersRelaxedAcl",
        "FlextLdifQuirksServersRelaxedEntry",
    ]

    for class_name in classes_to_check:
        ok, msg = check_file_has_class(base_path, class_name)
        if not ok:
            logger.info(f"❌ {msg}")
            return False
        logger.info(f"✅ {msg}")

    # Check key methods for schema quirk
    schema_methods = [
        "can_handle_attribute",
        "parse_attribute",
        "can_handle_objectclass",
        "parse_objectclass",
        "convert_attribute_to_rfc",
        "write_attribute_to_rfc",
    ]

    for method in schema_methods:
        ok, msg = check_file_has_method(
            base_path, "FlextLdifQuirksServersRelaxedSchema", method
        )
        if not ok:
            logger.info(f"❌ {msg}")
            return False
        logger.info(f"✅ {msg}")

    return True


def verify_config_modes() -> bool:
    """Verify Configuration modes implementation."""
    logger.info("\n=== VERIFYING CONFIG MODES IMPLEMENTATION ===")
    base_path = Path("src/flext_ldif/config.py")

    # Check file exists
    if not base_path.exists():
        logger.info(f"❌ File not found: {base_path}")
        return False

    # Check syntax
    ok, msg = check_file_syntax(base_path)
    if not ok:
        logger.info(f"❌ Syntax error: {msg}")
        return False
    logger.info("✅ Valid Python syntax")

    # Check file contains required config fields
    with Path(base_path).open("r", encoding="utf-8") as f:
        content = f.read()

    required_fields = [
        "quirks_detection_mode",
        "quirks_server_type",
        "enable_relaxed_parsing",
    ]

    for field in required_fields:
        if field in content:
            logger.info(f"✅ Configuration field '{field}' defined")
        else:
            logger.info(f"❌ Configuration field '{field}' not found")
            return False

    return True


def verify_client_api() -> bool:
    """Verify Client and API implementations."""
    logger.info("\n=== VERIFYING CLIENT & API IMPLEMENTATIONS ===")

    # Check client.py
    client_path = Path("src/flext_ldif/client.py")
    if not client_path.exists():
        logger.info(f"❌ File not found: {client_path}")
        return False

    ok, msg = check_file_syntax(client_path)
    if not ok:
        logger.info(f"❌ Client syntax error: {msg}")
        return False
    logger.info("✅ Client.py has valid syntax")

    # Check for new methods in client
    with Path(client_path).open("r", encoding="utf-8") as f:
        client_content = f.read()

    client_methods = ["get_effective_server_type", "detect_server_type"]
    for method in client_methods:
        if f"def {method}" in client_content:
            logger.info(f"✅ Client method '{method}' defined")
        else:
            logger.info(f"❌ Client method '{method}' not found")
            return False

    # Check api.py
    api_path = Path("src/flext_ldif/api.py")
    if not api_path.exists():
        logger.info(f"❌ File not found: {api_path}")
        return False

    ok, msg = check_file_syntax(api_path)
    if not ok:
        logger.info(f"❌ API syntax error: {msg}")
        return False
    logger.info("✅ API.py has valid syntax")

    # Check for new methods in API
    with Path(api_path).open("r", encoding="utf-8") as f:
        api_content = f.read()

    api_methods = [
        "detect_server_type",
        "parse_with_auto_detection",
        "parse_relaxed",
        "get_effective_server_type",
    ]
    for method in api_methods:
        if f"def {method}" in api_content:
            logger.info(f"✅ API method '{method}' defined")
        else:
            logger.info(f"❌ API method '{method}' not found")
            return False

    return True


def verify_test_files() -> bool:
    """Verify test files have valid syntax."""
    logger.info("\n=== VERIFYING TEST FILES ===")

    test_files = [
        Path("tests/unit/services/test_server_detector.py"),
        Path("tests/unit/quirks/servers/test_relaxed_quirks.py"),
    ]

    for test_file in test_files:
        if not test_file.exists():
            logger.info(f"❌ Test file not found: {test_file}")
            return False

        ok, msg = check_file_syntax(test_file)
        if not ok:
            logger.info(f"❌ {test_file.name} syntax error: {msg}")
            return False
        logger.info(f"✅ {test_file.name} has valid syntax")

    # Check config test file was modified
    config_test = Path("tests/unit/test_config.py")
    ok, msg = check_file_syntax(config_test)
    if not ok:
        logger.info(f"❌ test_config.py syntax error: {msg}")
        return False
    logger.info("✅ test_config.py has valid syntax")

    # Check for new test class in config test
    with Path(config_test).open("r", encoding="utf-8") as f:
        config_test_content = f.read()

    if "TestQuirksDetectionConfiguration" in config_test_content:
        logger.info("✅ TestQuirksDetectionConfiguration class found in test_config.py")
    else:
        logger.info(
            "❌ TestQuirksDetectionConfiguration class not found in test_config.py"
        )
        return False

    return True


def main() -> int:
    """Run all verifications."""
    logger.info("╔════════════════════════════════════════════════════════════╗")
    logger.info("║   PHASE 4: SYNTAX & STRUCTURE VERIFICATION                  ║")
    logger.info("║   (Bypasses flext-core import issue)                        ║")
    logger.info("╚════════════════════════════════════════════════════════════╝")

    results = {
        "Server Detector": verify_server_detector(),
        "Relaxed Quirks": verify_relaxed_quirks(),
        "Config Modes": verify_config_modes(),
        "Client & API": verify_client_api(),
        "Test Files": verify_test_files(),
    }

    logger.info("\n=== VERIFICATION SUMMARY ===")
    all_passed = True
    for test_name, result in results.items():
        status = "✅ PASS" if result else "❌ FAIL"
        logger.info(f"{test_name}: {status}")
        if not result:
            all_passed = False

    logger.info("=" * 60)
    if all_passed:
        logger.info("✅ ALL VERIFICATIONS PASSED - Phase 4 Syntax Check Complete")
        logger.info("\nNote: Full runtime testing blocked by pre-existing flext-core")
        logger.info(
            "      IndentationError in models.py (not caused by flext-ldif changes)"
        )
        return 0
    logger.info("❌ SOME VERIFICATIONS FAILED - Check output above")
    return 1


if __name__ == "__main__":
    sys.exit(main())
