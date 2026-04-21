"""LDIF domain models — MRO composition of all domain model mixins.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_ldif import (
    FlextLdifModelsDomainAcl,
    FlextLdifModelsDomainAttributes,
    FlextLdifModelsDomainDN,
    FlextLdifModelsDomainEntry,
    FlextLdifModelsDomainMetadata,
    FlextLdifModelsDomainSchema,
)


class FlextLdifModelsDomainsEntries(
    FlextLdifModelsDomainEntry,
    FlextLdifModelsDomainMetadata,
    FlextLdifModelsDomainAcl,
    FlextLdifModelsDomainAttributes,
    FlextLdifModelsDomainSchema,
    FlextLdifModelsDomainDN,
):
    """LDIF domain models — composed via MRO from domain mixins."""


__all__: list[str] = ["FlextLdifModelsDomainsEntries"]
