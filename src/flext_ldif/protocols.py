# AUTO-GENERATED FILE — Regenerate with: make gen
"""LDIF protocol facade.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_cli import p as flext_cli_p

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


class FlextLdifProtocols(flext_cli_p):
    """Unified LDIF protocol facade."""

    class Ldif(
        FlextLdifProtocolsBase,
        FlextLdifProtocolsClient,
        FlextLdifProtocolsDomain,
        FlextLdifProtocolsGeneratedModelsBaseModel,
        FlextLdifLdifProtocolsGeneratedModelsAclEntryConversion,
        FlextLdifLdifProtocolsGeneratedModelsEntryDetectionMarkers,
        FlextLdifLdifProtocolsGeneratedModelsEntryStatistics,
        FlextLdifLdifProtocolsGeneratedModelsSchemaElement,
        FlextLdifLdifProtocolsGeneratedModelsServerMetadata,
        FlextLdifLdifProtocolsGeneratedModelsValidationMetadata,
        FlextLdifProtocolsLdap3,
        FlextLdifProtocolsValues,
    ):
        """LDIF-specific structural protocol namespace.

        ``LdifSettings``, ``Settings``, and ``ServerResolutionService`` have a
        single owner in ``FlextLdifProtocolsBase`` and are inherited unchanged.
        """


p = FlextLdifProtocols
__all__: list[str] = ["FlextLdifProtocols", "p"]
