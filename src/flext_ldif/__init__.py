# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
"""Flext ldif package."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING as _TYPE_CHECKING

from flext_core.lazy import install_lazy_exports, merge_lazy_imports

from flext_ldif.__version__ import (
    __author__,
    __author_email__,
    __description__,
    __license__,
    __title__,
    __url__,
    __version__,
    __version_info__,
)

if _TYPE_CHECKING:
    from flext_core import FlextTypes, d, e, h, r, x

    from flext_ldif import (
        _models,
        _utilities,
        api,
        base,
        constants,
        models,
        protocols,
        servers,
        services,
        settings,
        shared,
        typings,
        utilities,
    )
    from flext_ldif._models import (
        FlextLdifModelsBases,
        FlextLdifModelsCollections,
        FlextLdifModelsDomains,
        FlextLdifModelsDomainsEntries,
        FlextLdifModelsEvents,
        FlextLdifModelsMetadata,
        FlextLdifModelsProcessing,
        FlextLdifModelsResults,
        FlextLdifModelsSettings,
        collections,
        domain,
        domain_entries,
        events,
        metadata,
        processing,
        results,
    )
    from flext_ldif._utilities import (
        FlextLdifUtilitiesACL,
        FlextLdifUtilitiesAttribute,
        FlextLdifUtilitiesCollectionLdif,
        FlextLdifUtilitiesDetection,
        FlextLdifUtilitiesDispatch,
        FlextLdifUtilitiesDN,
        FlextLdifUtilitiesEntry,
        FlextLdifUtilitiesEvents,
        FlextLdifUtilitiesMetadata,
        FlextLdifUtilitiesObjectClass,
        FlextLdifUtilitiesOID,
        FlextLdifUtilitiesParser,
        FlextLdifUtilitiesParsers,
        FlextLdifUtilitiesPipeline,
        FlextLdifUtilitiesResult,
        FlextLdifUtilitiesSchema,
        FlextLdifUtilitiesServer,
        FlextLdifUtilitiesTransformer,
        FlextLdifUtilitiesTransformers,
        FlextLdifUtilitiesValidation,
        FlextLdifUtilitiesWriter,
        FlextLdifUtilitiesWriters,
        acl,
        attribute,
        collection_ldif,
        detection,
        dispatch,
        dn,
        entry,
        object_class,
        oid,
        parser,
        parsers,
        pipeline,
        result,
        schema,
        server,
        transformers,
        validation,
        writer,
        writers,
    )
    from flext_ldif.api import FlextLdif, ldif
    from flext_ldif.base import FlextLdifServiceBase, s
    from flext_ldif.constants import FlextLdifConstants, FlextLdifConstants as c
    from flext_ldif.models import FlextLdifModels, FlextLdifModels as m
    from flext_ldif.protocols import FlextLdifProtocols, FlextLdifProtocols as p
    from flext_ldif.servers import (
        FlextLdifServersAd,
        FlextLdifServersApache,
        FlextLdifServersBase,
        FlextLdifServersDs389,
        FlextLdifServersNovell,
        FlextLdifServersOid,
        FlextLdifServersOpenldap,
        FlextLdifServersOpenldap1,
        FlextLdifServersOud,
        FlextLdifServersRelaxed,
        FlextLdifServersRfc,
        FlextLdifServersTivoli,
        ad,
        apache,
        ds389,
        logger,
        novell,
        openldap,
        openldap1,
        oud,
        relaxed,
        rfc,
        tivoli,
    )
    from flext_ldif.servers._base import (
        FlextLdifQuirkMethodsMixin,
        FlextLdifServersBaseConstants,
        FlextLdifServersBaseEntry,
        FlextLdifServersBaseQuirkHelpers,
        FlextLdifServersBaseSchema,
        FlextLdifServersBaseSchemaAcl,
    )
    from flext_ldif.servers._oid import (
        FlextLdifServersOidAcl,
        FlextLdifServersOidConstants,
        FlextLdifServersOidEntry,
        FlextLdifServersOidSchema,
    )
    from flext_ldif.servers._oud import (
        FlextLdifServersOudAcl,
        FlextLdifServersOudConstants,
        FlextLdifServersOudEntry,
        FlextLdifServersOudSchema,
        FlextLdifServersOudUtilities,
    )
    from flext_ldif.servers._rfc import (
        FlextLdifServersRfcAcl,
        FlextLdifServersRfcConstants,
        FlextLdifServersRfcEntry,
        FlextLdifServersRfcSchema,
    )
    from flext_ldif.services import (
        FlextLdifAcl,
        FlextLdifAnalysis,
        FlextLdifCategorization,
        FlextLdifConversion,
        FlextLdifDetector,
        FlextLdifDetectorMixin,
        FlextLdifEntries,
        FlextLdifFilters,
        FlextLdifMigrationPipeline,
        FlextLdifParser,
        FlextLdifParserMixin,
        FlextLdifProcessing,
        FlextLdifProcessingPipeline,
        FlextLdifServer,
        FlextLdifStatistics,
        FlextLdifTransformer,
        FlextLdifValidation,
        FlextLdifWriter,
        FlextLdifWriterMixin,
        analysis,
        categorization,
        conversion,
        detector,
        entries,
        filters,
        migration,
        rfc_validation,
        statistics,
    )
    from flext_ldif.services._services import (
        FlextLdifProcessingPipelineService,
        processing_pipeline_service,
    )
    from flext_ldif.settings import FlextLdifSettings
    from flext_ldif.shared import FlextLdifShared
    from flext_ldif.typings import FlextLdifTypes, FlextLdifTypes as t
    from flext_ldif.utilities import FlextLdifUtilities, FlextLdifUtilities as u

_LAZY_IMPORTS: Mapping[str, str | Sequence[str]] = merge_lazy_imports(
    (
        "flext_ldif._models",
        "flext_ldif._utilities",
        "flext_ldif.servers",
        "flext_ldif.services",
    ),
    {
        "FlextLdif": "flext_ldif.api",
        "FlextLdifConstants": "flext_ldif.constants",
        "FlextLdifModels": "flext_ldif.models",
        "FlextLdifProtocols": "flext_ldif.protocols",
        "FlextLdifServiceBase": "flext_ldif.base",
        "FlextLdifSettings": "flext_ldif.settings",
        "FlextLdifShared": "flext_ldif.shared",
        "FlextLdifTypes": "flext_ldif.typings",
        "FlextLdifUtilities": "flext_ldif.utilities",
        "_models": "flext_ldif._models",
        "_utilities": "flext_ldif._utilities",
        "api": "flext_ldif.api",
        "base": "flext_ldif.base",
        "c": ("flext_ldif.constants", "FlextLdifConstants"),
        "constants": "flext_ldif.constants",
        "d": "flext_core",
        "e": "flext_core",
        "h": "flext_core",
        "ldif": "flext_ldif.api",
        "m": ("flext_ldif.models", "FlextLdifModels"),
        "models": "flext_ldif.models",
        "p": ("flext_ldif.protocols", "FlextLdifProtocols"),
        "protocols": "flext_ldif.protocols",
        "r": "flext_core",
        "s": "flext_ldif.base",
        "servers": "flext_ldif.servers",
        "services": "flext_ldif.services",
        "settings": "flext_ldif.settings",
        "shared": "flext_ldif.shared",
        "t": ("flext_ldif.typings", "FlextLdifTypes"),
        "typings": "flext_ldif.typings",
        "u": ("flext_ldif.utilities", "FlextLdifUtilities"),
        "utilities": "flext_ldif.utilities",
        "x": "flext_core",
    },
)


install_lazy_exports(
    __name__,
    globals(),
    _LAZY_IMPORTS,
    [
        "__author__",
        "__author_email__",
        "__description__",
        "__license__",
        "__title__",
        "__url__",
        "__version__",
        "__version_info__",
    ],
)
