# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
"""Flext ldif package."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING

from flext_core.lazy import install_lazy_exports, merge_lazy_imports

if TYPE_CHECKING:
    from flext_ldif.__version__ import *
    from flext_ldif._models import *
    from flext_ldif._utilities import *
    from flext_ldif.api import *
    from flext_ldif.base import *
    from flext_ldif.constants import *
    from flext_ldif.models import *
    from flext_ldif.protocols import *
    from flext_ldif.servers import *
    from flext_ldif.servers._base import *
    from flext_ldif.servers._oid import *
    from flext_ldif.servers._oud import *
    from flext_ldif.servers._rfc import *
    from flext_ldif.services import *
    from flext_ldif.services._services import *
    from flext_ldif.settings import *
    from flext_ldif.shared import *
    from flext_ldif.typings import *
    from flext_ldif.utilities import *

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
        "__author__": "flext_ldif.__version__",
        "__author_email__": "flext_ldif.__version__",
        "__description__": "flext_ldif.__version__",
        "__license__": "flext_ldif.__version__",
        "__title__": "flext_ldif.__version__",
        "__url__": "flext_ldif.__version__",
        "__version__": "flext_ldif.__version__",
        "__version_info__": "flext_ldif.__version__",
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


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS)
