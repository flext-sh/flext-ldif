# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
"""Tests for flext_ldif._utilities.oid module."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING as _TYPE_CHECKING

from flext_core.lazy import install_lazy_exports

if _TYPE_CHECKING:
    from flext_core import FlextTypes
    from tests.unit._utilities.oid import test_oid_utilities
    from tests.unit._utilities.oid.test_oid_utilities import TestFlextLdifUtilitiesOID

_LAZY_IMPORTS: Mapping[str, str | Sequence[str]] = {
    "TestFlextLdifUtilitiesOID": "tests.unit._utilities.oid.test_oid_utilities",
    "test_oid_utilities": "tests.unit._utilities.oid.test_oid_utilities",
}


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS)
