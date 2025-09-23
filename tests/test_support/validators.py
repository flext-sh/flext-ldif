"""Test validators for LDIF functionality.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import re
from pathlib import Path

from flext_core import FlextResult, FlextTypes, T
from flext_ldif import FlextLdifModels


class TestValidators:
    """Validators for testing LDIF functionality."""

    @staticmethod
    def validate_ldif_entry(entry: FlextLdifModels.Entry) -> dict[str, bool]:
        """Validate a real LDIF entry object."""
        validations = {
            "has_dn": bool(entry.dn and str(entry.dn).strip()),
            "has_attributes": bool(entry.attributes and len(entry.attributes) > 0),
            "has_object_class": "objectClass" in entry.attributes
            if entry.attributes
            else False,
            "dn_format_valid": bool(
                entry.dn and "=" in str(entry.dn) and "," in str(entry.dn),
            ),
        }

        # Check for required attributes based on objectClass
        if validations["has_object_class"] and entry.attributes:
            object_classes = entry.get_attribute("objectClass") or []
            # object_classes is already a list from get_attribute

            # Basic validation for common object classes
            object_classes_list: list[str] = (
                list(object_classes) if object_classes else []
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
        if not dn:
            return False

        # Basic DN format validation
        # Should have attribute=value pairs separated by commas
        dn_pattern = r"^([a-zA-Z][a-zA-Z0-9]*\s*=\s*[^,]+)(,\s*[a-zA-Z][a-zA-Z0-9]*\s*=\s*[^,]+)*$"
        return bool(re.match(dn_pattern, dn.strip()))

    @staticmethod
    def validate_attribute_name(attr_name: str) -> bool:
        """Validate LDAP attribute name format."""
        if not attr_name:
            return False

        # LDAP attribute names: start with letter, can contain letters, digits, hyphens
        attr_pattern = r"^[a-zA-Z][a-zA-Z0-9-]*$"
        return bool(re.match(attr_pattern, attr_name))

    @staticmethod
    def validate_result_success(result: FlextResult[T]) -> FlextTypes.Core.Dict:
        """Validate FlextResult success characteristics."""
        has_value = False
        value_type_name = None
        if result.is_success:
            try:
                has_value = result.value is not None
                value_type_name = type(result.value).__name__
            except (AttributeError, TypeError):
                pass

        return {
            "is_success": result.is_success,
            "has_value": has_value,
            "no_error": result.error is None,
            "value_type": value_type_name,
        }

    @staticmethod
    def validate_result_failure(result: FlextResult[object]) -> FlextTypes.Core.Dict:
        """Validate FlextResult failure characteristics."""
        return {
            "is_failure": result.is_failure,
            "has_error": result.error is not None,
            "error_type": type(result.error).__name__ if result.error else None,
            "error_message": str(result.error) if result.error else None,
        }

    @staticmethod
    def validate_ldif_content(content: str) -> FlextTypes.Core.Dict:
        """Validate raw LDIF content format."""
        if not content:
            return {"is_valid": False, "reason": "Empty or non-string content"}

        lines = content.strip().split("\n")
        entry_count = 0
        current_dn = None

        for raw_line in lines:
            line = raw_line.strip()
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
        file_path: Path,
        expected_content: str,
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
        cls,
        result: FlextResult[list[FlextLdifModels.Entry]],
        expected_count: int,
    ) -> FlextTypes.Core.Dict:
        """Validate parsing result comprehensively."""
        base_validation = cls.validate_result_success(result)

        if not base_validation["is_success"]:
            return {**base_validation, "entries_valid": False}

        entries = result.value if hasattr(result, "value") else []
        entry_validations_list: list[dict[str, bool | int | str | None]] = []
        entries_validation: dict[
            str, bool | int | list[dict[str, bool | int | str | None]]
        ] = {
            "count_matches": len(entries) == expected_count,
            "actual_count": len(entries),
            "expected_count": expected_count,
            "all_entries_valid": True,
            "entry_validations": entry_validations_list,
        }

        # Validate each entry
        for i, entry in enumerate(entries):
            entry_validation = cls.validate_ldif_entry(entry)
            entry_validations_list.append(
                {
                    "index": i,
                    "dn": str(entry.dn) if entry.dn else None,
                    **entry_validation,
                },
            )

            if not all(entry_validation.values()):
                entries_validation["all_entries_valid"] = False

        return {**base_validation, **entries_validation}

    @staticmethod
    def assert_valid_ldif_entry(entry: FlextLdifModels.Entry) -> None:
        """Assert that an LDIF entry is valid (for use in tests)."""
        validation = TestValidators.validate_ldif_entry(entry)

        assert validation["has_dn"], f"Entry missing DN: {entry}"
        assert validation["has_attributes"], f"Entry missing attributes: {entry}"
        assert validation["dn_format_valid"], f"Invalid DN format: {entry.dn}"

    @staticmethod
    def assert_successful_result(result: FlextResult[T]) -> None:
        """Assert that a FlextResult is successful (for use in tests)."""
        validation = TestValidators.validate_result_success(result)

        assert validation["is_success"], f"Result failed: {result.error}"
        assert validation["has_value"], f"Result missing value: {result}"
        assert validation["no_error"], f"Result has error: {result.error}"
