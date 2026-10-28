# AUTO-GENERATED FILE — Regenerate with: make gen
"""Flext Ldif. Protocols package.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import (
    Iterable,
    Iterator,
    Mapping,
    MutableMapping,
    MutableSequence,
    Sequence,
)

from types import MappingProxyType
from typing import TYPE_CHECKING

from flext_core.lazy import install_lazy_exports

if TYPE_CHECKING:
    from flext_ldif._protocols.base import FlextLdifProtocolsBase
    from flext_ldif._protocols.client import FlextLdifProtocolsClient
    from flext_ldif._protocols.domain import FlextLdifProtocolsDomain
    from flext_ldif._protocols.generated_models_basemodel import (
        FlextLdifProtocolsModelsGeneratedBaseModel,
    )
    from flext_ldif._protocols.generated_models_ldif_aclentryconversion import (
        FlextLdifProtocolsModelsLdifGeneratedAclEntryConversion,
    )
    from flext_ldif._protocols.generated_models_ldif_entrydetectionmarkers import (
        FlextLdifProtocolsModelsLdifGeneratedEntryDetectionMarkers,
    )
    from flext_ldif._protocols.generated_models_ldif_entrystatistics import (
        FlextLdifProtocolsModelsLdifGeneratedEntryStatistics,
    )
    from flext_ldif._protocols.generated_models_ldif_schemaelement import (
        FlextLdifProtocolsModelsLdifGeneratedSchemaElement,
    )
    from flext_ldif._protocols.generated_models_ldif_servermetadata import (
        FlextLdifProtocolsModelsLdifGeneratedServerMetadata,
    )
    from flext_ldif._protocols.generated_models_ldif_validationmetadata import (
        FlextLdifProtocolsModelsLdifGeneratedValidationMetadata,
    )
    from flext_ldif._protocols.ldap3 import FlextLdifProtocolsLdap3
    from flext_ldif._protocols.values import FlextLdifProtocolsValues


__all__: tuple[str, ...] = (
    "FlextLdifProtocolsBase",
    "FlextLdifProtocolsClient",
    "FlextLdifProtocolsDomain",
    "FlextLdifProtocolsLdap3",
    "FlextLdifProtocolsModelsGeneratedBaseModel",
    "FlextLdifProtocolsModelsLdifGeneratedAclEntryConversion",
    "FlextLdifProtocolsModelsLdifGeneratedEntryDetectionMarkers",
    "FlextLdifProtocolsModelsLdifGeneratedEntryStatistics",
    "FlextLdifProtocolsModelsLdifGeneratedSchemaElement",
    "FlextLdifProtocolsModelsLdifGeneratedServerMetadata",
    "FlextLdifProtocolsModelsLdifGeneratedValidationMetadata",
    "FlextLdifProtocolsValues",
)

install_lazy_exports(
    __name__,
    globals(),
    MappingProxyType({
        "FlextLdifProtocolsModelsLdifGeneratedAclEntryConversion": (
            ".generated_models_ldif_aclentryconversion"
        ),
        "FlextLdifProtocolsModelsLdifGeneratedEntryDetectionMarkers": (
            ".generated_models_ldif_entrydetectionmarkers"
        ),
        "FlextLdifProtocolsModelsLdifGeneratedEntryStatistics": (
            ".generated_models_ldif_entrystatistics"
        ),
        "FlextLdifProtocolsModelsLdifGeneratedSchemaElement": (
            ".generated_models_ldif_schemaelement"
        ),
        "FlextLdifProtocolsModelsLdifGeneratedServerMetadata": (
            ".generated_models_ldif_servermetadata"
        ),
        "FlextLdifProtocolsModelsLdifGeneratedValidationMetadata": (
            ".generated_models_ldif_validationmetadata"
        ),
        "FlextLdifProtocolsBase": ".base",
        "FlextLdifProtocolsClient": ".client",
        "FlextLdifProtocolsDomain": ".domain",
        "FlextLdifProtocolsModelsGeneratedBaseModel": ".generated_models_basemodel",
        "FlextLdifProtocolsLdap3": ".ldap3",
        "FlextLdifProtocolsValues": ".values",
    }),
    public_exports=__all__,
)
