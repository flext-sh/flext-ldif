# AUTO-GENERATED FILE — Regenerate with: make gen
"""Flext Ldif. Protocols package.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from types import MappingProxyType
from typing import TYPE_CHECKING

from flext_core.lazy import install_lazy_exports

if TYPE_CHECKING:
    from flext_ldif._protocols.base import FlextLdifProtocolsBase
    from flext_ldif._protocols.client import FlextLdifProtocolsClient
    from flext_ldif._protocols.domain import FlextLdifProtocolsDomain
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
    from flext_ldif._protocols.values import FlextLdifProtocolsValues


__all__: tuple[str, ...] = (
    "FlextLdifLdifProtocolsGeneratedModelsAclEntryConversion",
    "FlextLdifLdifProtocolsGeneratedModelsEntryDetectionMarkers",
    "FlextLdifLdifProtocolsGeneratedModelsEntryStatistics",
    "FlextLdifLdifProtocolsGeneratedModelsSchemaElement",
    "FlextLdifLdifProtocolsGeneratedModelsServerMetadata",
    "FlextLdifLdifProtocolsGeneratedModelsValidationMetadata",
    "FlextLdifProtocolsBase",
    "FlextLdifProtocolsClient",
    "FlextLdifProtocolsDomain",
    "FlextLdifProtocolsGeneratedModelsBaseModel",
    "FlextLdifProtocolsLdap3",
    "FlextLdifProtocolsValues",
)

install_lazy_exports(
    __name__,
    globals(),
    MappingProxyType({
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
        "FlextLdifProtocolsBase": ".base",
        "FlextLdifProtocolsClient": ".client",
        "FlextLdifProtocolsDomain": ".domain",
        "FlextLdifProtocolsGeneratedModelsBaseModel": ".generated_models_basemodel",
        "FlextLdifProtocolsLdap3": ".ldap3",
        "FlextLdifProtocolsValues": ".values",
    }),
    public_exports=__all__,
)
