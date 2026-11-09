# AUTO-GENERATED FILE — Regenerate with: make gen
"""LDIF protocol facade.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_cli import FlextCliProtocols

from flext_ldif._protocols import (
    FlextLdifLdifProtocolsGeneratedModelsAclEntryConversion,
    FlextLdifLdifProtocolsGeneratedModelsEntryDetectionMarkers,
    FlextLdifLdifProtocolsGeneratedModelsEntryStatistics,
    FlextLdifLdifProtocolsGeneratedModelsSchemaElement,
    FlextLdifLdifProtocolsGeneratedModelsServerMetadata,
    FlextLdifLdifProtocolsGeneratedModelsValidationMetadata,
    FlextLdifProtocolsAclConvert,
    FlextLdifProtocolsBase,
    FlextLdifProtocolsClient,
    FlextLdifProtocolsCollections,
    FlextLdifProtocolsComposite,
    FlextLdifProtocolsDomain,
    FlextLdifProtocolsDomainAcl,
    FlextLdifProtocolsDomainAttributes,
    FlextLdifProtocolsDomainDn,
    FlextLdifProtocolsDomainEntry,
    FlextLdifProtocolsDomainEntryChange,
    FlextLdifProtocolsDomainEntryChangeValue,
    FlextLdifProtocolsDomainEntryControl,
    FlextLdifProtocolsDomainEntryStatistics,
    FlextLdifProtocolsDomainMetadata,
    FlextLdifProtocolsDomainSchema,
    FlextLdifProtocolsElements,
    FlextLdifProtocolsEvents,
    FlextLdifProtocolsGeneratedModelsBaseModel,
    FlextLdifProtocolsLdap3,
    FlextLdifProtocolsProcessing,
    FlextLdifProtocolsResults,
    FlextLdifProtocolsResultsStatistics,
    FlextLdifProtocolsSettings,
    FlextLdifProtocolsValues,
)


class FlextLdifProtocols(FlextCliProtocols):
    """Unified LDIF protocol facade."""

    class Ldif(
        FlextLdifProtocolsAclConvert,
        FlextLdifProtocolsBase,
        FlextLdifProtocolsClient,
        FlextLdifProtocolsCollections,
        FlextLdifProtocolsComposite,
        FlextLdifProtocolsDomain,
        FlextLdifProtocolsDomainAcl,
        FlextLdifProtocolsDomainAttributes,
        FlextLdifProtocolsDomainDn,
        FlextLdifProtocolsDomainEntry,
        FlextLdifProtocolsDomainEntryChange,
        FlextLdifProtocolsDomainEntryChangeValue,
        FlextLdifProtocolsDomainEntryControl,
        FlextLdifProtocolsDomainEntryStatistics,
        FlextLdifProtocolsDomainMetadata,
        FlextLdifProtocolsDomainSchema,
        FlextLdifProtocolsElements,
        FlextLdifProtocolsEvents,
        FlextLdifProtocolsGeneratedModelsBaseModel,
        FlextLdifLdifProtocolsGeneratedModelsAclEntryConversion,
        FlextLdifLdifProtocolsGeneratedModelsEntryDetectionMarkers,
        FlextLdifLdifProtocolsGeneratedModelsEntryStatistics,
        FlextLdifLdifProtocolsGeneratedModelsSchemaElement,
        FlextLdifLdifProtocolsGeneratedModelsServerMetadata,
        FlextLdifLdifProtocolsGeneratedModelsValidationMetadata,
        FlextLdifProtocolsLdap3,
        FlextLdifProtocolsProcessing,
        FlextLdifProtocolsResults,
        FlextLdifProtocolsResultsStatistics,
        FlextLdifProtocolsSettings,
        FlextLdifProtocolsValues,
    ):
        """LDIF-specific structural protocol namespace.

        ``LdifSettings``, ``Settings``, and ``ServerResolutionService`` have a
        single owner in ``FlextLdifProtocolsBase`` and are inherited unchanged.
        """


p = FlextLdifProtocols
__all__: list[str] = ["FlextLdifProtocols", "p"]
