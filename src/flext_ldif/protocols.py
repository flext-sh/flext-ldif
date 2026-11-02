# AUTO-GENERATED FILE — Regenerate with: make gen
"""LDIF protocol facade.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_cli import p as flext_cli_p

from flext_ldif._protocols import (
    FlextLdifProtocolsBase,
    FlextLdifProtocolsClient,
    FlextLdifProtocolsDomain,
    FlextLdifProtocolsLdap3,
    FlextLdifProtocolsValues,
)
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


class FlextLdifProtocols(flext_cli_p):
    """Unified LDIF protocol facade."""

    class Ldif(
        FlextLdifProtocolsDomain,
        FlextLdifProtocolsBase,
        FlextLdifProtocolsLdap3,
        FlextLdifProtocolsValues,
        FlextLdifProtocolsClient,
        FlextLdifProtocolsGeneratedModelsBaseModel,
        FlextLdifLdifProtocolsGeneratedModelsAclEntryConversion,
        FlextLdifLdifProtocolsGeneratedModelsEntryDetectionMarkers,
        FlextLdifLdifProtocolsGeneratedModelsEntryStatistics,
        FlextLdifLdifProtocolsGeneratedModelsSchemaElement,
        FlextLdifLdifProtocolsGeneratedModelsServerMetadata,
        FlextLdifLdifProtocolsGeneratedModelsValidationMetadata,
    ):
        """LDIF-specific structural protocol namespace.

        ``LdifSettings``, ``Settings``, and ``ServerResolutionService`` have a
        single owner in ``FlextLdifProtocolsBase`` and are inherited unchanged.
        """


p = FlextLdifProtocols
__all__: list[str] = ["FlextLdifProtocols", "p"]
