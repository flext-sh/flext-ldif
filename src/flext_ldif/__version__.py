# AUTO-GENERATED FILE — Regenerate with: make gen
"""Package version and metadata for flext-ldif.

Subclass of ``FlextVersion`` — overrides only ``_metadata``.
All derived attributes (``__version__``, ``__title__``, etc.) are
computed automatically via ``FlextVersion.__init_subclass__``.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from importlib.metadata import PackageMetadata, metadata

from flext_core import FlextVersion, t


class FlextLdifVersion(FlextVersion):
    """flext-ldif version — MRO-derived from FlextVersion."""

    _metadata: PackageMetadata | t.StrMapping = metadata("flext-ldif")


__version__ = FlextLdifVersion.__version__
__version_info__ = FlextLdifVersion.__version_info__
__title__ = FlextLdifVersion.__title__
__description__ = FlextLdifVersion.__description__
__author__ = FlextLdifVersion.__author__
__author_email__ = FlextLdifVersion.__author_email__
__license__ = FlextLdifVersion.__license__
__url__ = FlextLdifVersion.__url__
__all__: list[str] = [
    "FlextLdifVersion",
    "__author__",
    "__author_email__",
    "__description__",
    "__license__",
    "__title__",
    "__url__",
    "__version__",
    "__version_info__",
]
