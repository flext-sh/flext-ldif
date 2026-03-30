# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
"""Constants package."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING

from flext_core.lazy import install_lazy_exports

if TYPE_CHECKING:
    from tests.unit.constants import test_acl_registry as test_acl_registry
    from tests.unit.constants.test_acl_registry import (
        GetAclAttributesServerType as GetAclAttributesServerType,
        IsAclAttributeType as IsAclAttributeType,
        TestsTestFlextLdifAclAttributeRegistry as TestsTestFlextLdifAclAttributeRegistry,
    )

_LAZY_IMPORTS: Mapping[str, Sequence[str]] = {
    "GetAclAttributesServerType": [
        "tests.unit.constants.test_acl_registry",
        "GetAclAttributesServerType",
    ],
    "IsAclAttributeType": [
        "tests.unit.constants.test_acl_registry",
        "IsAclAttributeType",
    ],
    "TestsTestFlextLdifAclAttributeRegistry": [
        "tests.unit.constants.test_acl_registry",
        "TestsTestFlextLdifAclAttributeRegistry",
    ],
    "test_acl_registry": ["tests.unit.constants.test_acl_registry", ""],
}

_EXPORTS: Sequence[str] = [
    "GetAclAttributesServerType",
    "IsAclAttributeType",
    "TestsTestFlextLdifAclAttributeRegistry",
    "test_acl_registry",
]


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS, _EXPORTS)
