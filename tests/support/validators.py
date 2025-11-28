"""Test validators for LDIF functionality.

Domain-specific validators for testing LDIF entries, DN format, attributes,
and parsing results. Generic FlextResult validation is delegated to flext-core.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from pathlib import Path
from typing import TypeVar

from flext_core import FlextResult, FlextUtilities
from flext_tests import FlextTestsMatchers, FlextTestsUtilities

from flext_ldif import FlextLdifConstants, FlextLdifModels
from tests.fixtures.typing import GenericFieldsDict

T = TypeVar("T")

# Constants for LDIF validation patterns
_DN_PATTERN = (
    r"^([a-zA-Z][a-zA-Z0-9]*\s*=\s*[^,]+)"
    r"(,\s*[a-zA-Z][a-zA-Z0-9]*\s*=\s*[^,]+)*$"
)


class TestValidators:
    """Validators for testing LDIF functionality.

    Delegates generic FlextResult validation to flext-core utilities.
    Only LDIF-specific validation methods are implemented here.

    """

    # Delegate generic FlextResult helpers to flext-core
    ResultHelpers = FlextTestsUtilities.ResultHelpers
    Matchers = FlextTestsMatchers

    # Expose FlextUtilities.Validation for pattern validation
    Validation = FlextUtilities.Validation

    @staticmethod
    def validate_ldif_entry(entry: FlextLdifModels.Entry) -> dict[str, bool]:
        """Validate a real LDIF entry object.

        Args:
            entry: LDIF entry to validate.

        Returns:
            Dictionary with validation results.

        """
        dn_str = str(entry.dn) if entry.dn else ""
        has_attrs = bool(entry.attributes and len(entry.attributes.attributes) > 0)

        validations: dict[str, bool] = {
            "has_dn": bool(dn_str.strip()),
            "has_attributes": has_attrs,
            "has_object_class": bool(
                entry.attributes and "objectclass" in entry.attributes.attributes,
            ),
            "dn_format_valid": bool(dn_str and "=" in dn_str and "," in dn_str),
        }

        if validations["has_object_class"] and entry.attributes:
            attr_values = entry.get_attribute_values("objectclass")
            classes = attr_values if isinstance(attr_values, list) else []

            if "person" in classes:
                validations["person_has_cn"] = "cn" in entry.attributes.attributes
                validations["person_has_sn"] = "sn" in entry.attributes.attributes

            if "inetOrgPerson" in classes:
                validations["inet_org_person_valid"] = (
                    "mail" in entry.attributes.attributes
                )

        return validations

    @staticmethod
    def validate_dn_format(dn: str) -> bool:
        """Validate DN format using FlextUtilities.Validation.validate_pattern."""
        if not dn:
            return False
        return FlextUtilities.Validation.validate_pattern(
            dn.strip(),
            _DN_PATTERN,
            "DN",
        ).is_success

    @staticmethod
    def validate_attribute_name(attr_name: str) -> bool:
        """Validate attribute name using FlextLdifConstants pattern."""
        if not attr_name:
            return False
        return FlextUtilities.Validation.validate_pattern(
            attr_name,
            FlextLdifConstants.LdifPatterns.ATTRIBUTE_NAME,
            "Attribute name",
        ).is_success

    @staticmethod
    def validate_ldif_content(content: str) -> GenericFieldsDict:
        """Validate raw LDIF content format."""
        if not content:
            return {"is_valid": False, "reason": "Empty or non-string content"}

        lines = content.strip().split("\n")
        entry_count = 0
        current_dn: str | None = None

        for raw_line in lines:
            line = raw_line.strip()
            if not line:
                if current_dn:
                    entry_count += 1
                    current_dn = None
                continue

            if line.startswith("dn:"):
                current_dn = line[3:].strip()
                if not TestValidators.validate_dn_format(current_dn):
                    return {"is_valid": False, "reason": f"Invalid DN: {current_dn}"}
            elif ":" in line:
                attr_name = line.split(":", 1)[0].strip()
                if not TestValidators.validate_attribute_name(attr_name):
                    return {"is_valid": False, "reason": f"Invalid attr: {attr_name}"}

        if current_dn:
            entry_count += 1

        return {"is_valid": True, "entry_count": entry_count, "total_lines": len(lines)}

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
                actual = file_path.read_text(encoding="utf-8")
                validations["file_readable"] = True
                validations["content_matches"] = (
                    actual.strip() == expected_content.strip()
                )
                validations["encoding_valid"] = True
            except UnicodeDecodeError:
                validations["encoding_valid"] = False
            except (ValueError, TypeError, AttributeError):
                pass

        return validations

    @classmethod
    def validate_parsing_result(
        cls,
        result: FlextResult[list[FlextLdifModels.Entry]],
        expected_count: int,
    ) -> GenericFieldsDict:
        """Validate parsing result comprehensively."""
        if not result.is_success:
            return {
                "is_success": False,
                "has_value": False,
                "no_error": False,
                "entries_valid": False,
                "error": result.error,
            }

        entries = result.value or []
        entry_validations = [
            {
                "index": i,
                "dn": str(e.dn) if e.dn else None,
                **cls.validate_ldif_entry(e),
            }
            for i, e in enumerate(entries)
        ]

        all_valid = all(
            all(v for k, v in ev.items() if isinstance(v, bool))
            for ev in entry_validations
        )

        return {
            "is_success": True,
            "has_value": True,
            "no_error": True,
            "count_matches": len(entries) == expected_count,
            "actual_count": len(entries),
            "expected_count": expected_count,
            "all_entries_valid": all_valid,
            "entry_validations": entry_validations,
        }

    @staticmethod
    def assert_valid_ldif_entry(entry: FlextLdifModels.Entry) -> None:
        """Assert that an LDIF entry is valid."""
        v = TestValidators.validate_ldif_entry(entry)
        assert v["has_dn"], f"Entry missing DN: {entry}"
        assert v["has_attributes"], f"Entry missing attributes: {entry}"
        assert v["dn_format_valid"], f"Invalid DN format: {entry.dn}"

    # Delegate to flext-core - use directly when possible
    assert_successful_result = staticmethod(FlextTestsMatchers.assert_success)
    validate_flext_result_composition = staticmethod(
        FlextTestsUtilities.ResultHelpers.validate_composition,
    )
    validate_flext_result_chain = staticmethod(
        FlextTestsUtilities.ResultHelpers.validate_chain,
    )
    assert_flext_result_composition = staticmethod(
        FlextTestsUtilities.ResultHelpers.assert_composition,
    )

    @staticmethod
    def assert_flext_result_chain(
        results: list[FlextResult[object]],
        *,
        expect_all_success: bool = True,
    ) -> None:
        """Assert FlextResult chain operations."""
        if expect_all_success:
            FlextTestsUtilities.ResultHelpers.assert_chain_success(results)
        else:
            chain = FlextTestsUtilities.ResultHelpers.validate_chain(results)
            assert not chain["is_valid_chain"], "Expected failures but all succeeded"

    @staticmethod
    def validate_result_success(result: FlextResult[T]) -> GenericFieldsDict:
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
            "has_error_code": result.error_code is not None,
            "has_error_data": bool(result.error_data),
            "error_code": result.error_code,
            "error_data_keys": list(result.error_data.keys())
            if result.error_data
            else [],
        }

    @staticmethod
    def validate_result_failure(result: FlextResult[T]) -> GenericFieldsDict:
        """Validate FlextResult failure characteristics."""
        return {
            "is_failure": result.is_failure,
            "has_error": result.error is not None,
            "error_type": type(result.error).__name__ if result.error else None,
            "error_message": str(result.error) if result.error else None,
            "has_error_code": result.error_code is not None,
            "has_error_data": bool(result.error_data),
            "error_code": result.error_code,
            "error_data_keys": list(result.error_data.keys())
            if result.error_data
            else [],
            "error_data_values": list(result.error_data.values())
            if result.error_data
            else [],
        }
