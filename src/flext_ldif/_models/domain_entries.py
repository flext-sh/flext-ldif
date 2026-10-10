"""LDIF domain models — MRO composition of all domain model mixins.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_ldif._models import FlextLdifModelsAclConvert
from flext_ldif._models import FlextLdifModelsDomainAcl
from flext_ldif._models import FlextLdifModelsDomainAttributes
from flext_ldif._models import FlextLdifModelsDomainDN
from flext_ldif._models import FlextLdifModelsDomainEntry
from flext_ldif._models import FlextLdifModelsDomainMetadata
from flext_ldif._models import FlextLdifModelsDomainSchema


class FlextLdifModelsDomainsEntries(
    FlextLdifModelsDomainEntry,
    FlextLdifModelsDomainMetadata,
    FlextLdifModelsAclConvert,
    FlextLdifModelsDomainAcl,
    FlextLdifModelsDomainAttributes,
    FlextLdifModelsDomainSchema,
    FlextLdifModelsDomainDN,
):
    """LDIF domain models — composed via MRO from domain mixins."""


__all__: list[str] = ["FlextLdifModelsDomainsEntries"]
