# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
"""Tests package."""

from __future__ import annotations

import typing as _t

from flext_core.lazy import install_lazy_exports

if _t.TYPE_CHECKING:
    from flext_core.decorators import FlextDecorators as d
    from flext_core.exceptions import FlextExceptions as e
    from flext_core.handlers import FlextHandlers as h
    from flext_core.mixins import FlextMixins as x
    from flext_core.result import FlextResult as r
    from tests.base import TestsFlextLdifServiceBase, TestsFlextLdifServiceBase as s
    from tests.constants import TestsFlextLdifConstants, TestsFlextLdifConstants as c
    from tests.models import TestsFlextLdifModels, TestsFlextLdifModels as m
    from tests.protocols import TestsFlextLdifProtocols, TestsFlextLdifProtocols as p
    from tests.typings import (
        GenericFieldsDict,
        TestsFlextLdifTypes,
        TestsFlextLdifTypes as t,
    )
    from tests.utilities import TestsFlextLdifUtilities, TestsFlextLdifUtilities as u
_LAZY_IMPORTS = {
    "GenericFieldsDict": ("tests.typings", "GenericFieldsDict"),
    "TestsFlextLdifConstants": ("tests.constants", "TestsFlextLdifConstants"),
    "TestsFlextLdifModels": ("tests.models", "TestsFlextLdifModels"),
    "TestsFlextLdifProtocols": ("tests.protocols", "TestsFlextLdifProtocols"),
    "TestsFlextLdifServiceBase": ("tests.base", "TestsFlextLdifServiceBase"),
    "TestsFlextLdifTypes": ("tests.typings", "TestsFlextLdifTypes"),
    "TestsFlextLdifUtilities": ("tests.utilities", "TestsFlextLdifUtilities"),
    "c": ("tests.constants", "TestsFlextLdifConstants"),
    "d": ("flext_core.decorators", "FlextDecorators"),
    "e": ("flext_core.exceptions", "FlextExceptions"),
    "h": ("flext_core.handlers", "FlextHandlers"),
    "m": ("tests.models", "TestsFlextLdifModels"),
    "p": ("tests.protocols", "TestsFlextLdifProtocols"),
    "r": ("flext_core.result", "FlextResult"),
    "s": ("tests.base", "TestsFlextLdifServiceBase"),
    "t": ("tests.typings", "TestsFlextLdifTypes"),
    "u": ("tests.utilities", "TestsFlextLdifUtilities"),
    "x": ("flext_core.mixins", "FlextMixins"),
}

__all__ = [
    "GenericFieldsDict",
    "TestsFlextLdifConstants",
    "TestsFlextLdifModels",
    "TestsFlextLdifProtocols",
    "TestsFlextLdifServiceBase",
    "TestsFlextLdifTypes",
    "TestsFlextLdifUtilities",
    "c",
    "d",
    "e",
    "h",
    "m",
    "p",
    "r",
    "s",
    "t",
    "u",
    "x",
]


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS)
