# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
"""Constants package."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING as _TYPE_CHECKING

from flext_core.lazy import install_lazy_exports

if _TYPE_CHECKING:
    from flext_core import FlextTypes

    from tests.unit.constants import test_acl_registry
    from tests.unit.constants.test_acl_registry import (
        GetAclAttributesServerType,
        IsAclAttributeType,
        TestsTestFlextLdifAclAttributeRegistry,
    )

_LAZY_IMPORTS: Mapping[str, str | Sequence[str]] = {
    "GetAclAttributesServerType": "tests.unit.constants.test_acl_registry",
    "IsAclAttributeType": "tests.unit.constants.test_acl_registry",
    "TestsTestFlextLdifAclAttributeRegistry": "tests.unit.constants.test_acl_registry",
    "test_acl_registry": "tests.unit.constants.test_acl_registry",
}


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS)
