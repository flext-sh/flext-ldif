"""FLEXT LDIF Validator Service - LDIF validation service implementation.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_core import FlextDomainService, FlextLogger, FlextResult
from flext_ldif.models import FlextLdifModels


class FlextLdifValidatorService(FlextDomainService[list[FlextLdifModels.Entry]]):
    """LDIF Validator Service - Using FlextLdifModels Pydantic v2 validation directly.

    Handles all LDIF validation operations using existing Pydantic v2 field validators
    in FlextLdifModels. No duplicate validation classes needed.
    """

    def __init__(self) -> None:
        """Initialize validator service."""
        super().__init__()
        self._logger = FlextLogger(__name__)

    def get_config_info(self) -> dict[str, object]:
        """Get service configuration information."""
        return {
            "service": "FlextLdifValidatorService",
            "config": {
                "service_type": "validator",
                "status": "ready",
                "capabilities": [
                    "validate_entries",
                    "validate_entry",
                    "validate_entry_structure",
                    "validate_dn_format",
                ],
            },
        }

    def get_service_info(self) -> dict[str, object]:
        """Get service information."""
        return {
            "service_name": "FlextLdifValidatorService",
            "service_type": "validator",
            "capabilities": [
                "validate_entries",
                "validate_entry",
                "validate_entry_structure",
                "validate_dn_format",
            ],
            "status": "ready",
        }

    def validate_entries(
        self, entries: list[FlextLdifModels.Entry]
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Validate multiple LDIF entries using FlextLdifModels validation."""
        if not entries:
            return FlextResult[list[FlextLdifModels.Entry]].fail(
                "Cannot validate empty entry list"
            )

        validated_entries: list[FlextLdifModels.Entry] = []

        for entry in entries:
            # Use FlextLdifModels Entry business rules validation
            validation_result = entry.validate_business_rules()
            if validation_result.is_failure:
                return FlextResult[list[FlextLdifModels.Entry]].fail(
                    f"Entry validation failed: {validation_result.error}"
                )
            validated_entries.append(entry)

        return FlextResult[list[FlextLdifModels.Entry]].ok(validated_entries)

    def validate_entry(self, entry: FlextLdifModels.Entry) -> FlextResult[bool]:
        """Validate single LDIF entry using FlextLdifModels validation."""
        # Use FlextLdifModels Entry business rules validation
        validation_result = entry.validate_business_rules()
        if validation_result.is_failure:
            return FlextResult[bool].fail(
                validation_result.error or "Validation failed"
            )
        return FlextResult[bool].ok(data=True)

    def validate_entry_structure(
        self, entry: FlextLdifModels.Entry
    ) -> FlextResult[bool]:
        """Validate entry structure using FlextLdifModels validation."""
        return self.validate_entry(entry)

    def validate_dn_format(self, dn: str) -> FlextResult[bool]:
        """Validate DN format using FlextLdifModels DistinguishedName validation."""
        try:
            # Use FlextLdifModels DistinguishedName Pydantic v2 validation
            dn_obj = FlextLdifModels.DistinguishedName(value=dn)
            validation_result = dn_obj.validate_business_rules()
            if validation_result.is_failure:
                return FlextResult[bool].fail(
                    validation_result.error or "DN validation failed"
                )
            return FlextResult[bool].ok(data=True)
        except Exception as e:
            return FlextResult[bool].fail(f"DN validation failed: {e}")

    def execute(self) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Execute validator operation - returns sample validated entries."""
        # Create sample entries for testing
        sample_entries = [
            FlextLdifModels.Entry(
                dn=FlextLdifModels.DistinguishedName(
                    value="cn=test1,dc=example,dc=com"
                ),
                attributes=FlextLdifModels.LdifAttributes(
                    data={"cn": ["test1"], "objectClass": ["person"]}
                ),
            ),
            FlextLdifModels.Entry(
                dn=FlextLdifModels.DistinguishedName(
                    value="cn=test2,dc=example,dc=com"
                ),
                attributes=FlextLdifModels.LdifAttributes(
                    data={"cn": ["test2"], "objectClass": ["person"]}
                ),
            ),
            FlextLdifModels.Entry(
                dn=FlextLdifModels.DistinguishedName(
                    value="cn=test3,dc=example,dc=com"
                ),
                attributes=FlextLdifModels.LdifAttributes(
                    data={"cn": ["test3"], "objectClass": ["person"]}
                ),
            ),
        ]

        return FlextResult[list[FlextLdifModels.Entry]].ok(sample_entries)


__all__ = ["FlextLdifValidatorService"]
