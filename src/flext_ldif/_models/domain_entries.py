"""LDIF domain models — MRO composition of all domain model mixins.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from .acl_convert import FlextLdifModelsAclConvert
from .domain_acl import FlextLdifModelsDomainAcl
from .domain_attributes import FlextLdifModelsDomainAttributes
from .domain_dn import FlextLdifModelsDomainDN
from .domain_entry import FlextLdifModelsDomainEntry
from .domain_metadata import FlextLdifModelsDomainMetadata
from .domain_schema import FlextLdifModelsDomainSchema


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
