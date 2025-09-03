"""Test Validators for LDIF Testing.

Provides validation utilities for testing real LDIF functionality
and ensuring correct behavior without relying on mocks.
"""

from __future__ import annotations

import re
from pathlib import Path

from flext_core import FlextResult

from flext_ldif import FlextLDIFModels


class TestValidators:
    """Validators for testing LDIF functionality."""

    @staticmethod
    def validate_ldif_entry(entry: FlextLDIFModels.Entry) -> dict[str, bool]:
        """Validate a real LDIF entry object."""
        validations = {
            "has_dn": bool(entry.dn and str(entry.dn).strip()),
            "has_attributes": bool(entry.attributes and len(entry.attributes) > 0),
            "has_object_class": "objectClass" in entry.attributes
            if entry.attributes
            else False,
            "dn_format_valid": bool(
                entry.dn and "=" in str(entry.dn) and "," in str(entry.dn)
            ),
        }

        # Check for required attributes based on objectClass
        if validations["has_object_class"] and entry.attributes:
            object_classes = entry.attributes.get("objectClass", [])
            if isinstance(object_classes, str):
                object_classes = [object_classes]

            # Basic validation for common object classes
            object_classes_list = (
                list(object_classes)
                if isinstance(object_classes, list)
                else [object_classes]
                if object_classes
                else []
            )
            if "person" in object_classes_list:
                validations["person_has_cn"] = "cn" in entry.attributes
                validations["person_has_sn"] = "sn" in entry.attributes

            if "inetOrgPerson" in object_classes_list:
                validations["inet_org_person_valid"] = "mail" in entry.attributes

        return validations

    @staticmethod
    def validate_dn_format(dn: str) -> bool:
        """Validate DN format according to RFC standards."""
        if not dn or not isinstance(dn, str):
            return False

        # Basic DN format validation
        # Should have attribute=value pairs separated by commas
        dn_pattern = r"^([a-zA-Z][a-zA-Z0-9]*\s*=\s*[^,]+)(,\s*[a-zA-Z][a-zA-Z0-9]*\s*=\s*[^,]+)*$"
        return bool(re.match(dn_pattern, dn.strip()))

    @staticmethod
    def validate_attribute_name(attr_name: str) -> bool:
        """Validate LDAP attribute name format."""
        if not attr_name or not isinstance(attr_name, str):
            return False

        # LDAP attribute names: start with letter, can contain letters, digits, hyphens
        attr_pattern = r"^[a-zA-Z][a-zA-Z0-9-]*$"
        return bool(re.match(attr_pattern, attr_name))

    @staticmethod
    def validate_result_success(result: FlextResult[object]) -> dict[str, object]:
        """Validate FlextResult success characteristics."""
        return {
            "is_success": result.is_success,
            "has_value": hasattr(result, "value") and result.value is not None,
            "no_error": result.error is None,
            "value_type": type(result.value).__name__
            if hasattr(result, "value")
            else None,
        }

    @staticmethod
    def validate_result_failure(result: FlextResult[object]) -> dict[str, object]:
        """Validate FlextResult failure characteristics."""
        return {
            "is_failure": result.is_failure,
            "has_error": result.error is not None,
            "error_type": type(result.error).__name__ if result.error else None,
            "error_message": str(result.error) if result.error else None,
        }

    @staticmethod
    def validate_ldif_content(content: str) -> dict[str, object]:
        """Validate raw LDIF content format."""
        if not content or not isinstance(content, str):
            return {"is_valid": False, "reason": "Empty or non-string content"}

        lines = content.strip().split("\n")
        entry_count = 0
        current_dn = None

        for line in lines:
            line = line.strip()
            if not line:  # Empty line separates entries
                if current_dn:
                    entry_count += 1
                    current_dn = None
                continue

            if line.startswith("dn:"):
                current_dn = line[3:].strip()
                if not TestValidators.validate_dn_format(current_dn):
                    return {
                        "is_valid": False,
                        "reason": f"Invalid DN format: {current_dn}",
                    }
            elif ":" in line:
                attr_name = line.split(":", 1)[0].strip()
                if not TestValidators.validate_attribute_name(attr_name):
                    return {
                        "is_valid": False,
                        "reason": f"Invalid attribute name: {attr_name}",
                    }

        # Count last entry if file doesn't end with empty line
        if current_dn:
            entry_count += 1

        return {
            "is_valid": True,
            "entry_count": entry_count,
            "total_lines": len(lines),
        }

    @staticmethod
    def validate_file_operations(
        file_path: Path, expected_content: str
    ) -> dict[str, bool]:
        """Validate file operations for LDIF files."""
        validations = {
            "file_exists": file_path.exists(),
            "file_readable": False,
            "content_matches": False,
            "encoding_valid": False,
        }

        if validations["file_exists"]:
            try:
                actual_content = file_path.read_text(encoding="utf-8")
                validations["file_readable"] = True
                validations["content_matches"] = (
                    actual_content.strip() == expected_content.strip()
                )
                validations["encoding_valid"] = True
            except UnicodeDecodeError:
                validations["encoding_valid"] = False
            except Exception:
                validations["file_readable"] = False

        return validations

    @classmethod
    def validate_parsing_result(
        cls, result: FlextResult[list[FlextLDIFModels.Entry]], expected_count: int
    ) -> dict[str, object]:
        """Validate parsing result comprehensively."""
        base_validation = cls.validate_result_success(result)

        if not base_validation["is_success"]:
            return {**base_validation, "entries_valid": False}

        entries = result.value if hasattr(result, "value") else []
        entries_validation = {
            "count_matches": len(entries) == expected_count,
            "actual_count": len(entries),
            "expected_count": expected_count,
            "all_entries_valid": True,
            "entry_validations": [],
        }

        # Validate each entry
        for i, entry in enumerate(entries):
            entry_validation = cls.validate_ldif_entry(entry)
            entries_validation["entry_validations"].append(
                {
                    "index": i,
                    "dn": str(entry.dn) if entry.dn else None,
                    **entry_validation,
                }
            )

            if not all(entry_validation.values()):
                entries_validation["all_entries_valid"] = False

        return {**base_validation, **entries_validation}

    @staticmethod
    def assert_valid_ldif_entry(entry: FlextLDIFModels.Entry) -> None:
        """Assert that an LDIF entry is valid (for use in tests)."""
        validation = TestValidators.validate_ldif_entry(entry)

        assert validation["has_dn"], f"Entry missing DN: {entry}"
        assert validation["has_attributes"], f"Entry missing attributes: {entry}"
        assert validation["dn_format_valid"], f"Invalid DN format: {entry.dn}"

    @staticmethod
    def assert_successful_result(result: FlextResult[object]) -> None:
        """Assert that a FlextResult is successful (for use in tests)."""
        validation = TestValidators.validate_result_success(result)

        assert validation["is_success"], f"Result failed: {result.error}"
        assert validation["has_value"], f"Result missing value: {result}"
        assert validation["no_error"], f"Result has error: {result.error}"
