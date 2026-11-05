"""Serialization contracts for immutable LDIF rule views.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from types import MappingProxyType

from tests import c, m, p, tm


@c.Tests.MARK.parametrize(
    ("rules", "field"),
    [
        (m.Ldif.CategoryRules(), "category_markers"),
        (m.Ldif.WhitelistRules(), "schema_oid_filters"),
    ],
)
def test_rule_views_remain_immutable_and_serialize(
    rules: p.BaseModel,
    field: str,
) -> None:
    """Serialize the real computed view without mutating the model contract."""
    tm.that(isinstance(getattr(rules, field), MappingProxyType))
    tm.that(isinstance(rules.model_dump()[field], dict))
    tm.that(isinstance(rules.model_dump(mode="json")[field], dict))
    tm.that(bool(rules.model_dump_json()))
