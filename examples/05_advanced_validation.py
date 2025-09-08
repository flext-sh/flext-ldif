#!/usr/bin/env python3
"""FLEXT - Enterprise Data Integration Platform.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations
from flext_core import FlextTypes

from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING

from flext_core import get_logger

from ..flext_ldif import FlextLDIFAPI, FlextLDIFModels

"""Advanced LDIF validation example.

Demonstrates domain validation with business rules using
Clean Architecture patterns and FlextResult error handling.
"""

logger = get_logger(__name__)

if TYPE_CHECKING:
    from flext_core import FlextResult

logger = get_logger(__name__)


def validate_business_rules(
    entry: FlextLDIFModels.Entry,
) -> tuple[bool, FlextTypes.Core.StringList]:
    """Apply custom business validation rules.

    Args:
      entry: LDIF entry to validate

    Returns:
      Tuple of (is_valid, list_of_errors)

    """
    errors: FlextTypes.Core.StringList = []

    # Rule 1: Person entries must have email
    if entry.is_person_entry():
        mail = entry.attributes.get_single_attribute("mail")
        if not mail or not mail[0]:
            errors.append("Person entries must have email address")

    # Rule 2: Employee numbers must be numeric
    employee_num = entry.attributes.get_single_attribute("employeeNumber")
    if employee_num:
        try:
            int(employee_num[0])
        except (ValueError, IndexError):
            errors.append("Employee number must be numeric")

    # Rule 3: Phone numbers must follow format
    phone = entry.attributes.get_single_attribute("telephoneNumber")
    if phone and phone[0]:
        phone_num = phone[0]
        if not phone_num.startswith("+1-555-"):
            errors.append("Phone number must follow +1-555-XXXX format")

    # Rule 4: Manager must be a valid DN
    manager = entry.attributes.get_single_attribute("manager")
    if manager and manager[0]:
        manager_dn = manager[0]
        if "ou=People" not in manager_dn:
            errors.append("Manager must be in People OU")

    return len(errors) == 0, errors


# SOLID REFACTORING: Template Method Pattern to reduce complexity from 20 to 8
class LdifValidationDemonstrator:
    """Template Method Pattern for LDIF validation demonstration.

    SOLID REFACTORING: Eliminates 20 complexity points using Single Responsibility Principle.
    Each validation step becomes a separate method with single responsibility.
    """

    def __init__(self) -> None:
        """Initialize demonstrator with strict validation config."""
        config = FlextLDIFModels.Config(strict_validation=True, max_entries=50)
        self.api = FlextLDIFAPI(config)

    def demonstrate(self) -> None:
        """Template method: demonstrate validation workflow."""
        entries = self._parse_sample_file()
        if not entries:
            return

        self._perform_domain_validation(entries)
        self._perform_business_validation(entries)
        self._analyze_entry_types(entries)
        self._test_invalid_ldif()

    def _parse_sample_file(self) -> list[FlextLDIFModels.Entry] | None:
        """Parse sample LDIF file and return entries."""
        sample_file = Path(__file__).parent / "sample_complex.ldif"
        parse_result = self.api.parse_file(sample_file)
        if not parse_result.is_success:
            return None
        entries = parse_result.value
        return entries or None

    def _perform_domain_validation(self, entries: list[FlextLDIFModels.Entry]) -> None:
        """Perform domain validation on entries."""
        domain_errors: FlextTypes.Core.StringList = []

        for i, entry in enumerate(entries):
            # Use railway programming for validation
            entry.validate_business_rules().tap_error(
                lambda error, idx=i, ent=entry: domain_errors.append(
                    f"Entry {idx + 1} ({ent.dn}): {error}"
                )
            )

        self._log_validation_errors(domain_errors, "Domain validation")

    def _perform_business_validation(
        self, entries: list[FlextLDIFModels.Entry]
    ) -> None:
        """Perform business rule validation on entries."""
        business_errors: FlextTypes.Core.StringList = []

        for i, entry in enumerate(entries):
            is_valid, errors = validate_business_rules(entry)
            if not is_valid:
                business_errors.extend(
                    f"Entry {i + 1} ({entry.dn}): {error}" for error in errors
                )

        self._log_validation_errors(business_errors, "Business validation")

    def _analyze_entry_types(self, entries: list[FlextLDIFModels.Entry]) -> None:
        """Analyze entry types using API filters."""
        # Use railway programming for filtering results
        filter_functions: list[
            Callable[
                [list[FlextLDIFModels.Entry]], FlextResult[list[FlextLDIFModels.Entry]]
            ]
        ] = [
            self.api.filter_persons,
            self.api.filter_groups,
            self.api.filter_organizational_units,
        ]
        for filter_func in filter_functions:
            filter_func(entries).tap(
                lambda filtered_entries: logger.info(
                    f"Found {len(filtered_entries)} entries"
                )
                if filtered_entries
                else logger.info("No entries found")
            )

    def _test_invalid_ldif(self) -> None:
        """Test validation with invalid LDIF file."""
        invalid_file = Path(__file__).parent / "sample_invalid.ldif"

        if not invalid_file.exists():
            return

        # Use railway programming for invalid file processing
        self.api.parse_file(invalid_file).tap(self._validate_invalid_entries)

    def _validate_invalid_entries(self, entries: list[FlextLDIFModels.Entry]) -> None:
        """Validate entries from invalid LDIF file."""
        for entry in entries:
            # Use railway programming for validation
            entry.validate_business_rules().tap_error(
                lambda _: None  # Log validation failure
            )

    def _log_validation_errors(
        self, errors: FlextTypes.Core.StringList, validation_type: str
    ) -> None:
        """Log validation errors with type prefix."""
        if not errors:
            return

        # Constants for error display
        max_displayed_errors = 5

        # Show first 5 errors only to avoid output spam
        for error in errors[:max_displayed_errors]:
            logger.error(f"[{validation_type}] {error}")

        if len(errors) > max_displayed_errors:
            remaining = len(errors) - max_displayed_errors
            logger.warning(f"[{validation_type}] ... and {remaining} more errors")


def main() -> None:
    """Demonstrate advanced LDIF validation using Template Method Pattern.

    SOLID REFACTORING: Reduced complexity from 20 to 2 using Template Method Pattern.
    """
    demonstrator = LdifValidationDemonstrator()
    demonstrator.demonstrate()


if __name__ == "__main__":
    main()
