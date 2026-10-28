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
        FlextLdifModelsProtocolsGeneratedBaseModel,
    )
    from flext_ldif._protocols.generated_models_ldif_aclentryconversion import (
        FlextLdifModelsProtocolsLdifGeneratedAclEntryConversion,
    )
    from flext_ldif._protocols.generated_models_ldif_entrydetectionmarkers import (
        FlextLdifModelsProtocolsLdifGeneratedEntryDetectionMarkers,
    )
    from flext_ldif._protocols.generated_models_ldif_entrystatistics import (
        FlextLdifModelsProtocolsLdifGeneratedEntryStatistics,
    )
    from flext_ldif._protocols.generated_models_ldif_schemaelement import (
        FlextLdifModelsProtocolsLdifGeneratedSchemaElement,
    )
    from flext_ldif._protocols.generated_models_ldif_servermetadata import (
        FlextLdifModelsProtocolsLdifGeneratedServerMetadata,
    )
    from flext_ldif._protocols.generated_models_ldif_validationmetadata import (
        FlextLdifModelsProtocolsLdifGeneratedValidationMetadata,
    )
    from flext_ldif._protocols.ldap3 import FlextLdifProtocolsLdap3
    from flext_ldif._protocols.values import FlextLdifProtocolsValues


__all__: tuple[str, ...] = (
    "FlextLdifModelsProtocolsGeneratedBaseModel",
    "FlextLdifModelsProtocolsLdifGeneratedAclEntryConversion",
    "FlextLdifModelsProtocolsLdifGeneratedEntryDetectionMarkers",
    "FlextLdifModelsProtocolsLdifGeneratedEntryStatistics",
    "FlextLdifModelsProtocolsLdifGeneratedSchemaElement",
    "FlextLdifModelsProtocolsLdifGeneratedServerMetadata",
    "FlextLdifModelsProtocolsLdifGeneratedValidationMetadata",
    "FlextLdifProtocolsBase",
    "FlextLdifProtocolsClient",
    "FlextLdifProtocolsDomain",
    "FlextLdifProtocolsLdap3",
    "FlextLdifProtocolsValues",
)

install_lazy_exports(
    __name__,
    globals(),
    MappingProxyType({
        "FlextLdifModelsProtocolsLdifGeneratedAclEntryConversion": (
            ".generated_models_ldif_aclentryconversion"
        ),
        "FlextLdifModelsProtocolsLdifGeneratedEntryDetectionMarkers": (
            ".generated_models_ldif_entrydetectionmarkers"
        ),
        "FlextLdifModelsProtocolsLdifGeneratedEntryStatistics": (
            ".generated_models_ldif_entrystatistics"
        ),
        "FlextLdifModelsProtocolsLdifGeneratedSchemaElement": (
            ".generated_models_ldif_schemaelement"
        ),
        "FlextLdifModelsProtocolsLdifGeneratedServerMetadata": (
            ".generated_models_ldif_servermetadata"
        ),
        "FlextLdifModelsProtocolsLdifGeneratedValidationMetadata": (
            ".generated_models_ldif_validationmetadata"
        ),
        "FlextLdifProtocolsBase": ".base",
        "FlextLdifProtocolsClient": ".client",
        "FlextLdifProtocolsDomain": ".domain",
        "FlextLdifModelsProtocolsGeneratedBaseModel": ".generated_models_basemodel",
        "FlextLdifProtocolsLdap3": ".ldap3",
        "FlextLdifProtocolsValues": ".values",
    }),
    public_exports=__all__,
)
