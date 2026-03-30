# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
"""Flext ldif package."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING

from flext_core.lazy import install_lazy_exports

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

if TYPE_CHECKING:
    from flext_core import *

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
        collections,
        domain,
        domain_entries,
        events,
        metadata,
        processing,
        results,
    )
    from flext_ldif._models.base import *
    from flext_ldif._models.collections import *
    from flext_ldif._models.domain import *
    from flext_ldif._models.domain_entries import *
    from flext_ldif._models.events import *
    from flext_ldif._models.metadata import *
    from flext_ldif._models.processing import *
    from flext_ldif._models.results import *
    from flext_ldif._models.settings import *
    from flext_ldif._utilities import (
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
    from flext_ldif._utilities.acl import *
    from flext_ldif._utilities.attribute import *
    from flext_ldif._utilities.collection_ldif import *
    from flext_ldif._utilities.detection import *
    from flext_ldif._utilities.dispatch import *
    from flext_ldif._utilities.dn import *
    from flext_ldif._utilities.entry import *
    from flext_ldif._utilities.events import *
    from flext_ldif._utilities.metadata import *
    from flext_ldif._utilities.object_class import *
    from flext_ldif._utilities.oid import *
    from flext_ldif._utilities.parser import *
    from flext_ldif._utilities.parsers import *
    from flext_ldif._utilities.pipeline import *
    from flext_ldif._utilities.result import *
    from flext_ldif._utilities.schema import *
    from flext_ldif._utilities.server import *
    from flext_ldif._utilities.transformers import *
    from flext_ldif._utilities.validation import *
    from flext_ldif._utilities.writer import *
    from flext_ldif._utilities.writers import *
    from flext_ldif.api import *
    from flext_ldif.base import *
    from flext_ldif.constants import *
    from flext_ldif.models import *
    from flext_ldif.protocols import *
    from flext_ldif.servers import (
        ad,
        apache,
        ds389,
        novell,
        openldap,
        openldap1,
        oud,
        relaxed,
        rfc,
        tivoli,
    )
    from flext_ldif.servers._base.acl import *
    from flext_ldif.servers._base.constants import *
    from flext_ldif.servers._base.entry import *
    from flext_ldif.servers._base.schema import *
    from flext_ldif.servers._oid.acl import *
    from flext_ldif.servers._oid.constants import *
    from flext_ldif.servers._oid.entry import *
    from flext_ldif.servers._oid.schema import *
    from flext_ldif.servers._oud.acl import *
    from flext_ldif.servers._oud.constants import *
    from flext_ldif.servers._oud.entry import *
    from flext_ldif.servers._oud.schema import *
    from flext_ldif.servers._oud.utilities import *
    from flext_ldif.servers._rfc.acl import *
    from flext_ldif.servers._rfc.constants import *
    from flext_ldif.servers._rfc.entry import *
    from flext_ldif.servers._rfc.schema import *
    from flext_ldif.servers.ad import *
    from flext_ldif.servers.apache import *
    from flext_ldif.servers.base import *
    from flext_ldif.servers.ds389 import *
    from flext_ldif.servers.novell import *
    from flext_ldif.servers.oid import *
    from flext_ldif.servers.openldap import *
    from flext_ldif.servers.openldap1 import *
    from flext_ldif.servers.oud import *
    from flext_ldif.servers.relaxed import *
    from flext_ldif.servers.rfc import *
    from flext_ldif.servers.tivoli import *
    from flext_ldif.services import (
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
    from flext_ldif.services._services import processing_pipeline_service
    from flext_ldif.services._services.processing_pipeline_service import *
    from flext_ldif.services.acl import *
    from flext_ldif.services.analysis import *
    from flext_ldif.services.categorization import *
    from flext_ldif.services.conversion import *
    from flext_ldif.services.detector import *
    from flext_ldif.services.entries import *
    from flext_ldif.services.filters import *
    from flext_ldif.services.migration import *
    from flext_ldif.services.parser import *
    from flext_ldif.services.pipeline import *
    from flext_ldif.services.processing import *
    from flext_ldif.services.rfc_validation import *
    from flext_ldif.services.server import *
    from flext_ldif.services.statistics import *
    from flext_ldif.services.transformers import *
    from flext_ldif.services.writer import *
    from flext_ldif.settings import *
    from flext_ldif.shared import *
    from flext_ldif.typings import *
    from flext_ldif.utilities import *

from flext_ldif._models import _LAZY_IMPORTS as __MODELS_LAZY
from flext_ldif._utilities import _LAZY_IMPORTS as __UTILITIES_LAZY
from flext_ldif.servers import _LAZY_IMPORTS as _SERVERS_LAZY
from flext_ldif.services import _LAZY_IMPORTS as _SERVICES_LAZY

_LAZY_IMPORTS: Mapping[str, str | Sequence[str]] = {
    **__MODELS_LAZY,
    **__UTILITIES_LAZY,
    **_SERVERS_LAZY,
    **_SERVICES_LAZY,
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
    "c": ["flext_ldif.constants", "FlextLdifConstants"],
    "constants": "flext_ldif.constants",
    "d": "flext_core",
    "e": "flext_core",
    "h": "flext_core",
    "ldif": "flext_ldif.api",
    "m": ["flext_ldif.models", "FlextLdifModels"],
    "models": "flext_ldif.models",
    "p": ["flext_ldif.protocols", "FlextLdifProtocols"],
    "protocols": "flext_ldif.protocols",
    "r": "flext_core",
    "s": "flext_ldif.base",
    "servers": "flext_ldif.servers",
    "services": "flext_ldif.services",
    "settings": "flext_ldif.settings",
    "shared": "flext_ldif.shared",
    "t": ["flext_ldif.typings", "FlextLdifTypes"],
    "typings": "flext_ldif.typings",
    "u": ["flext_ldif.utilities", "FlextLdifUtilities"],
    "utilities": "flext_ldif.utilities",
    "x": "flext_core",
}


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS, sorted(_LAZY_IMPORTS))
