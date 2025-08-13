"""FLEXT-LDIF Validator Service - Clean Architecture Infrastructure Layer.

ARCHITECTURAL CONSOLIDATION: This module contains the concrete LDIF validation service
following Clean Architecture patterns, extracted from infrastructure_services.py
for better separation of concerns.

ELIMINATED DUPLICATION:
✅ Extracted from infrastructure_services.py for single responsibility
✅ Uses base_service.py correctly without duplication
✅ Implements application protocols without local duplication
✅ Complete flext-core integration patterns

Service:
    - FlextLdifValidatorService: Concrete LDIF validation implementation with business rules

Technical Excellence:
    - Clean Architecture: Infrastructure layer implementing application protocols
    - ZERO duplication: Uses base_service.py and flext-core patterns correctly
    - SOLID principles: Single responsibility, dependency inversion
    - Type safety: Comprehensive type annotations with Python 3.13+

Author: FLEXT Development Team
Version: 0.9.0
License: MIT
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from flext_core import FlextDomainService, FlextResult, get_logger
from pydantic import Field

from flext_ldif.format_validators import LdifValidator

from .config import FlextLdifConfig

if TYPE_CHECKING:
    from .models import FlextLdifEntry

logger = get_logger(__name__)


class FlextLdifValidatorService(FlextDomainService[bool]):
    """Validate LDIF entries applying business and configuration rules.

    This service implements validation logic for LDIF objects following
    Clean Architecture and flext-core patterns.
    """

    config: FlextLdifConfig | None = Field(default=None)

    def execute(self) -> FlextResult[bool]:
        """Execute validation operation.

        Performs a no-op sanity check of the configured rules. This method is
        intentionally lightweight and delegates real validation work to
        validate_entry/validate_entries.

        Returns:
            FlextResult[bool]: Success if configuration is valid.

        """
        # If a config is present, validate its business rules
        if self.config is not None:
            cfg_validation = self.config.validate_business_rules()
            if cfg_validation.is_failure:
                return FlextResult.fail(cfg_validation.error or "Invalid configuration")
        return FlextResult.ok(data=True)

    def validate_data(self, data: list[FlextLdifEntry]) -> FlextResult[bool]:
        """Validate a list of LDIF entries.

        Args:
            data: Entries to validate.

        Returns:
            FlextResult[bool]: Success if all entries are valid.

        """
        return self.validate_entries(data)

    def validate_entry(self, entry: FlextLdifEntry) -> FlextResult[bool]:
        """Validate a single LDIF entry.

        Args:
            entry: Entry to validate.

        Returns:
            FlextResult[bool]: Success if the entry is valid; otherwise failure with message.

        """
        validation_result = entry.validate_business_rules()
        if validation_result.is_failure:
            return FlextResult.fail(
                f"Entry validation failed: {validation_result.error}",
            )

        # Enforce configuration-driven rules
        if (
            self.config is not None
            and self.config.strict_validation
            and not self.config.allow_empty_attributes
        ):
            # Empty attribute lists are not allowed in strict mode
            for attr_name, values in entry.attributes.attributes.items():
                if len(values) == 0:
                    return FlextResult.fail(
                        f"Empty attribute values not allowed for '{attr_name}' in strict mode",
                    )
                # Also disallow empty-string values strictly
                if any(
                    v is None or (isinstance(v, str) and v.strip() == "")
                    for v in values
                ):
                    return FlextResult.fail(
                        f"Empty attribute value not allowed for '{attr_name}' in strict mode",
                    )
        return FlextResult.ok(data=True)

    def validate_entries(self, entries: list[FlextLdifEntry]) -> FlextResult[bool]:
        """Validate multiple LDIF entries.

        Args:
            entries: Entries to validate.

        Returns:
            FlextResult[bool]: Success if all entries are valid.

        """
        for i, entry in enumerate(entries):
            entry_result = self.validate_entry(entry)
            if entry_result.is_failure:
                return FlextResult.fail(
                    f"Entry {i} validation failed: {entry_result.error}",
                )
        return FlextResult.ok(data=True)

    def validate_dn_format(self, dn: str) -> FlextResult[bool]:
        """Validate DN format compliance.

        Args:
            dn: Distinguished Name string to validate.

        Returns:
            FlextResult[bool]: Validation result from the consolidated validator.

        """
        # Delegate to consolidated validation that uses flext-ldap APIs
        return LdifValidator.validate_dn(dn)


__all__ = ["FlextLdifValidatorService"]

# Rebuild model to resolve forward references after config is defined
# Ensure forward-ref targets are available at runtime for Pydantic
try:
    from .config import FlextLdifConfig as _FlextLdifConfigRuntime
    globals()["FlextLdifConfig"] = _FlextLdifConfigRuntime
except Exception as _e:
    # Best-effort: if import fails, forward refs may resolve later
    ...

# Note: model_rebuild() is called in api.py to avoid circular imports
