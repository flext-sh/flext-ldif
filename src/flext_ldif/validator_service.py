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

import logging
from typing import TYPE_CHECKING

from flext_core import FlextDomainService, FlextResult
from pydantic import Field

if TYPE_CHECKING:
    from .config import FlextLdifConfig
    from .models import FlextLdifEntry

logger = logging.getLogger(__name__)


class FlextLdifValidatorService(FlextDomainService[bool]):
    """Concrete LDIF validation service using flext-core patterns."""

    config: FlextLdifConfig | None = Field(default=None)

    def execute(self) -> FlextResult[bool]:
        """Execute validation operation - required by FlextDomainService."""
        # This would be called with specific data in real usage
        return FlextResult.ok(data=True)

    def validate_data(self, data: list[FlextLdifEntry]) -> FlextResult[bool]:
        """Validate data using flext-core pattern."""
        return self.validate_entries(data)

    def validate_entry(self, entry: FlextLdifEntry) -> FlextResult[bool]:
        """Validate single LDIF entry."""
        validation_result = entry.validate_business_rules()
        if validation_result.is_failure:
            return FlextResult.fail(f"Entry validation failed: {validation_result.error}")
        return FlextResult.ok(data=True)

    def validate_entries(self, entries: list[FlextLdifEntry]) -> FlextResult[bool]:
        """Validate multiple LDIF entries."""
        for i, entry in enumerate(entries):
            entry_result = self.validate_entry(entry)
            if entry_result.is_failure:
                return FlextResult.fail(f"Entry {i} validation failed: {entry_result.error}")
        return FlextResult.ok(data=True)

    def validate_dn_format(self, dn: str) -> FlextResult[bool]:
        """Validate DN format compliance.
        
        ✅ ELIMINATED DUPLICATION: Delegates to validation.LdifValidator
        which properly delegates to flext-ldap root API.
        """
        # Import locally to avoid circular dependency
        from flext_ldif.validation import LdifValidator
        
        # Delegate to consolidated validation that uses flext-ldap APIs
        return LdifValidator.validate_dn(dn)


__all__ = ["FlextLdifValidatorService"]
