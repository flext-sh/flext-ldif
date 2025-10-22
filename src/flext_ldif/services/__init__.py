"""FLEXT-LDIF Services - Domain Services for LDIF Operations.

This package contains domain services that implement business logic
following FLEXT patterns with FlextService base class.

Services follow Single Responsibility Principle:
- Each service handles one domain concern
- Returns FlextResult for composable error handling
- Uses ldap3/ldif3 for RFC compliance
- Type-safe with Python 3.13+ annotations

Available Services:
- DnService: RFC 4514 compliant DN operations using ldap3
- ValidationService: RFC 2849/4512 compliant entry validation

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from flext_ldif.services.dn_service import FlextLdifDnService
from flext_ldif.services.server_detector import FlextLdifServerDetector
from flext_ldif.services.validation_service import FlextLdifValidationService
from flext_ldif.typings import FlextLdifTypes

__all__ = [
    "FlextLdifDnService",
    "FlextLdifServerDetector",
    "FlextLdifTypes",
    "FlextLdifValidationService",
]
