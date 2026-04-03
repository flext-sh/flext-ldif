# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
"""Support package."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING as _TYPE_CHECKING

from flext_core.lazy import install_lazy_exports

if _TYPE_CHECKING:
    from flext_core import FlextTypes
    from flext_core.constants import FlextConstants as c
    from flext_core.decorators import FlextDecorators as d
    from flext_core.exceptions import FlextExceptions as e
    from flext_core.handlers import FlextHandlers as h
    from flext_core.mixins import FlextMixins as x
    from flext_core.models import FlextModels as m
    from flext_core.protocols import FlextProtocols as p
    from flext_core.result import FlextResult as r
    from flext_core.service import FlextService as s
    from flext_core.typings import FlextTypes as t
    from flext_core.utilities import FlextUtilities as u
    from flext_ldif import (
        conftest_factory,
        ldif_data,
        real_services,
        test_files,
        validators,
    )
    from flext_ldif.conftest_factory import FlextLdifTestConftest, tk
    from flext_ldif.ldif_data import LdifSample
    from flext_ldif.real_services import FlextLdifTestServiceFactory
    from flext_ldif.test_files import FileManager
    from flext_ldif.validators import MockFlextUtilitiesResultHelpers

_LAZY_IMPORTS: FlextTypes.LazyImportIndex = {
    "FileManager": "flext_ldif.test_files",
    "FlextLdifTestConftest": "flext_ldif.conftest_factory",
    "FlextLdifTestServiceFactory": "flext_ldif.real_services",
    "LdifSample": "flext_ldif.ldif_data",
    "MockFlextUtilitiesResultHelpers": "flext_ldif.validators",
    "c": ("flext_core.constants", "FlextConstants"),
    "conftest_factory": "flext_ldif.conftest_factory",
    "d": ("flext_core.decorators", "FlextDecorators"),
    "e": ("flext_core.exceptions", "FlextExceptions"),
    "h": ("flext_core.handlers", "FlextHandlers"),
    "ldif_data": "flext_ldif.ldif_data",
    "m": ("flext_core.models", "FlextModels"),
    "p": ("flext_core.protocols", "FlextProtocols"),
    "r": ("flext_core.result", "FlextResult"),
    "real_services": "flext_ldif.real_services",
    "s": ("flext_core.service", "FlextService"),
    "t": ("flext_core.typings", "FlextTypes"),
    "test_files": "flext_ldif.test_files",
    "tk": "flext_ldif.conftest_factory",
    "u": ("flext_core.utilities", "FlextUtilities"),
    "validators": "flext_ldif.validators",
    "x": ("flext_core.mixins", "FlextMixins"),
}


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS)
