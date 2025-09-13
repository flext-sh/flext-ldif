"""FLEXT LDIF Validator Service - LDIF validation service implementation.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_core import FlextResult

from flext_ldif.base_service import FlextLDIFBaseService
from flext_ldif.format_validators import FlextLDIFFormatValidators
from flext_ldif.models import FlextLDIFModels


class FlextLDIFValidatorService(FlextLDIFBaseService[list[FlextLDIFModels.Entry]]):
    """LDIF Validator Service - Single Responsibility.

    Handles all LDIF validation operations with enterprise-grade error handling.
    Uses flext-core SOURCE OF TRUTH exclusively.
    """

    def __init__(
        self, format_validator: FlextLDIFFormatValidators | None = None
    ) -> None:
        """Initialize validator service."""
        super().__init__("FlextLDIFValidatorService", "validator")
        self._format_validator = format_validator or FlextLDIFFormatValidators()

        # Register capabilities
        self._add_capability("validate_entries")
        self._add_capability("validate_entry")
        self._add_capability("validate_entry_structure")
        self._add_capability("validate_dn_format")

    def validate_entries(
        self, entries: list[FlextLDIFModels.Entry]
    ) -> FlextResult[list[FlextLDIFModels.Entry]]:
        """Validate multiple LDIF entries."""
        try:
            if not entries:
                return FlextResult[list[FlextLDIFModels.Entry]].fail(
                    "Cannot validate empty entry list"
                )

            validated_entries: list[FlextLDIFModels.Entry] = []

            for entry in entries:
                validation_result = self._format_validator.validate_entry(entry)
                if validation_result.is_failure:
                    return FlextResult[list[FlextLDIFModels.Entry]].fail(
                        f"Entry validation failed: {validation_result.error}"
                    )
                validated_entries.append(entry)

            return FlextResult[list[FlextLDIFModels.Entry]].ok(validated_entries)
        except Exception as e:
            return self._handle_error("Validation", e)

    def validate_entry(self, entry: FlextLDIFModels.Entry) -> FlextResult[bool]:
        """Validate single LDIF entry."""
        try:
            validation_result = self._format_validator.validate_entry(entry)
            if validation_result.is_failure:
                return FlextResult[bool].fail(
                    validation_result.error or "Validation failed"
                )
            return FlextResult[bool].ok(data=True)
        except Exception as e:
            return self._handle_error_bool("Entry validation", e)

    def validate_entry_structure(
        self, entry: FlextLDIFModels.Entry
    ) -> FlextResult[bool]:
        """Validate entry structure - alias for validate_entry."""
        return self.validate_entry(entry)

    def validate_dn_format(self, dn: str) -> FlextResult[bool]:
        """Validate DN format."""
        try:
            if not dn or not dn.strip():
                return FlextResult[bool].fail("DN cannot be empty or whitespace only")

            # Basic DN format validation
            if not dn.strip():
                return FlextResult[bool].fail("DN cannot be empty")

            # Check for basic DN structure (contains = and ,)
            if "=" not in dn or "," not in dn:
                return FlextResult[bool].fail("Invalid DN format")

            return FlextResult[bool].ok(data=True)
        except Exception as e:
            return self._handle_error_bool("DN validation", e)

    def execute(self) -> FlextResult[list[FlextLDIFModels.Entry]]:
        """Execute validator operation - returns sample validated entries."""
        # Create sample entries for testing
        sample_entries = [
            FlextLDIFModels.Entry(
                dn=FlextLDIFModels.DistinguishedName(
                    value="cn=test1,dc=example,dc=com"
                ),
                attributes=FlextLDIFModels.LdifAttributes(
                    data={"cn": ["test1"], "objectClass": ["person"]}
                ),
            ),
            FlextLDIFModels.Entry(
                dn=FlextLDIFModels.DistinguishedName(
                    value="cn=test2,dc=example,dc=com"
                ),
                attributes=FlextLDIFModels.LdifAttributes(
                    data={"cn": ["test2"], "objectClass": ["person"]}
                ),
            ),
            FlextLDIFModels.Entry(
                dn=FlextLDIFModels.DistinguishedName(
                    value="cn=test3,dc=example,dc=com"
                ),
                attributes=FlextLDIFModels.LdifAttributes(
                    data={"cn": ["test3"], "objectClass": ["person"]}
                ),
            ),
        ]

        return FlextResult[list[FlextLDIFModels.Entry]].ok(sample_entries)


__all__ = ["FlextLDIFValidatorService"]
