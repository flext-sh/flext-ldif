# AUTO-GENERATED FILE — Regenerate with: make gen
"""Flext Ldif. Protocols package.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from flext_core.lazy import install_lazy_exports

if TYPE_CHECKING:
    from flext_ldif._protocols.acl_convert import FlextLdifProtocolsAclConvert
    from flext_ldif._protocols.base import FlextLdifProtocolsBase
    from flext_ldif._protocols.client import FlextLdifProtocolsClient
    from flext_ldif._protocols.collections import FlextLdifProtocolsCollections
    from flext_ldif._protocols.composite import FlextLdifProtocolsComposite
    from flext_ldif._protocols.domain import FlextLdifProtocolsDomain
    from flext_ldif._protocols.domain_acl import FlextLdifProtocolsDomainAcl
    from flext_ldif._protocols.domain_attributes import (
        FlextLdifProtocolsDomainAttributes,
    )
    from flext_ldif._protocols.domain_dn import FlextLdifProtocolsDomainDn
    from flext_ldif._protocols.domain_entry import FlextLdifProtocolsDomainEntry
    from flext_ldif._protocols.domain_entry_change import (
        FlextLdifProtocolsDomainEntryChange,
    )
    from flext_ldif._protocols.domain_entry_change_value import (
        FlextLdifProtocolsDomainEntryChangeValue,
    )
    from flext_ldif._protocols.domain_entry_control import (
        FlextLdifProtocolsDomainEntryControl,
    )
    from flext_ldif._protocols.domain_entry_statistics import (
        FlextLdifProtocolsDomainEntryStatistics,
    )
    from flext_ldif._protocols.domain_metadata import FlextLdifProtocolsDomainMetadata
    from flext_ldif._protocols.domain_schema import FlextLdifProtocolsDomainSchema
    from flext_ldif._protocols.elements import FlextLdifProtocolsElements
    from flext_ldif._protocols.events import FlextLdifProtocolsEvents
    from flext_ldif._protocols.generated_models_basemodel import (
        FlextLdifProtocolsGeneratedModelsBaseModel,
    )
    from flext_ldif._protocols.generated_models_ldif_aclentryconversion import (
        FlextLdifLdifProtocolsGeneratedModelsAclEntryConversion,
    )
    from flext_ldif._protocols.generated_models_ldif_entrydetectionmarkers import (
        FlextLdifLdifProtocolsGeneratedModelsEntryDetectionMarkers,
    )
    from flext_ldif._protocols.generated_models_ldif_entrystatistics import (
        FlextLdifLdifProtocolsGeneratedModelsEntryStatistics,
    )
    from flext_ldif._protocols.generated_models_ldif_schemaelement import (
        FlextLdifLdifProtocolsGeneratedModelsSchemaElement,
    )
    from flext_ldif._protocols.generated_models_ldif_servermetadata import (
        FlextLdifLdifProtocolsGeneratedModelsServerMetadata,
    )
    from flext_ldif._protocols.generated_models_ldif_validationmetadata import (
        FlextLdifLdifProtocolsGeneratedModelsValidationMetadata,
    )
    from flext_ldif._protocols.ldap3 import FlextLdifProtocolsLdap3
    from flext_ldif._protocols.processing import FlextLdifProtocolsProcessing
    from flext_ldif._protocols.results import FlextLdifProtocolsResults
    from flext_ldif._protocols.results_statistics import (
        FlextLdifProtocolsResultsStatistics,
    )
    from flext_ldif._protocols.settings import FlextLdifProtocolsSettings
    from flext_ldif._protocols.values import FlextLdifProtocolsValues


__all__: tuple[str, ...] = (
    "FlextLdifLdifProtocolsGeneratedModelsAclEntryConversion",
    "FlextLdifLdifProtocolsGeneratedModelsEntryDetectionMarkers",
    "FlextLdifLdifProtocolsGeneratedModelsEntryStatistics",
    "FlextLdifLdifProtocolsGeneratedModelsSchemaElement",
    "FlextLdifLdifProtocolsGeneratedModelsServerMetadata",
    "FlextLdifLdifProtocolsGeneratedModelsValidationMetadata",
    "FlextLdifProtocolsAclConvert",
    "FlextLdifProtocolsBase",
    "FlextLdifProtocolsClient",
    "FlextLdifProtocolsCollections",
    "FlextLdifProtocolsComposite",
    "FlextLdifProtocolsDomain",
    "FlextLdifProtocolsDomainAcl",
    "FlextLdifProtocolsDomainAttributes",
    "FlextLdifProtocolsDomainDn",
    "FlextLdifProtocolsDomainEntry",
    "FlextLdifProtocolsDomainEntryChange",
    "FlextLdifProtocolsDomainEntryChangeValue",
    "FlextLdifProtocolsDomainEntryControl",
    "FlextLdifProtocolsDomainEntryStatistics",
    "FlextLdifProtocolsDomainMetadata",
    "FlextLdifProtocolsDomainSchema",
    "FlextLdifProtocolsElements",
    "FlextLdifProtocolsEvents",
    "FlextLdifProtocolsGeneratedModelsBaseModel",
    "FlextLdifProtocolsLdap3",
    "FlextLdifProtocolsProcessing",
    "FlextLdifProtocolsResults",
    "FlextLdifProtocolsResultsStatistics",
    "FlextLdifProtocolsSettings",
    "FlextLdifProtocolsValues",
)

install_lazy_exports(
    __name__,
    globals(),
    {
        "FlextLdifLdifProtocolsGeneratedModelsAclEntryConversion": (
            ".generated_models_ldif_aclentryconversion"
        ),
        "FlextLdifLdifProtocolsGeneratedModelsEntryDetectionMarkers": (
            ".generated_models_ldif_entrydetectionmarkers"
        ),
        "FlextLdifLdifProtocolsGeneratedModelsEntryStatistics": (
            ".generated_models_ldif_entrystatistics"
        ),
        "FlextLdifLdifProtocolsGeneratedModelsSchemaElement": (
            ".generated_models_ldif_schemaelement"
        ),
        "FlextLdifLdifProtocolsGeneratedModelsServerMetadata": (
            ".generated_models_ldif_servermetadata"
        ),
        "FlextLdifLdifProtocolsGeneratedModelsValidationMetadata": (
            ".generated_models_ldif_validationmetadata"
        ),
        "FlextLdifProtocolsAclConvert": ".acl_convert",
        "FlextLdifProtocolsBase": ".base",
        "FlextLdifProtocolsClient": ".client",
        "FlextLdifProtocolsCollections": ".collections",
        "FlextLdifProtocolsComposite": ".composite",
        "FlextLdifProtocolsDomain": ".domain",
        "FlextLdifProtocolsDomainAcl": ".domain_acl",
        "FlextLdifProtocolsDomainAttributes": ".domain_attributes",
        "FlextLdifProtocolsDomainDn": ".domain_dn",
        "FlextLdifProtocolsDomainEntry": ".domain_entry",
        "FlextLdifProtocolsDomainEntryChange": ".domain_entry_change",
        "FlextLdifProtocolsDomainEntryChangeValue": ".domain_entry_change_value",
        "FlextLdifProtocolsDomainEntryControl": ".domain_entry_control",
        "FlextLdifProtocolsDomainEntryStatistics": ".domain_entry_statistics",
        "FlextLdifProtocolsDomainMetadata": ".domain_metadata",
        "FlextLdifProtocolsDomainSchema": ".domain_schema",
        "FlextLdifProtocolsElements": ".elements",
        "FlextLdifProtocolsEvents": ".events",
        "FlextLdifProtocolsGeneratedModelsBaseModel": ".generated_models_basemodel",
        "FlextLdifProtocolsLdap3": ".ldap3",
        "FlextLdifProtocolsProcessing": ".processing",
        "FlextLdifProtocolsResults": ".results",
        "FlextLdifProtocolsResultsStatistics": ".results_statistics",
        "FlextLdifProtocolsSettings": ".settings",
        "FlextLdifProtocolsValues": ".values",
    },
    public_exports=__all__,
)
