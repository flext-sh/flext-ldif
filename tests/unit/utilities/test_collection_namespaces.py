"""Regression coverage for collection contracts on the public LDIF facade.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_tests import tm

from tests import c, m, u


class TestsFlextLdifCollectionNamespaces:
    """Retain root Result search and domain optional-item search independently."""

    @staticmethod
    def test_root_find_preserves_result_contract() -> None:
        """Core search returns a Result for both matches and misses."""
        tm.that(tm.ok(u.find(["selected"], bool)), eq="selected")
        tm.fail(u.find([""], bool))

    @staticmethod
    def test_ldif_find_preserves_optional_item_contract() -> None:
        """Domain search returns the matching item or None."""
        tm.that(u.Ldif.find(["selected"], predicate=bool), eq="selected")
        tm.that(u.Ldif.find([""], predicate=bool), none=True)

    @staticmethod
    def test_collection_helpers_retain_both_public_entry_points() -> None:
        """Separating search does not remove normalization helpers."""
        tm.that(u.deduplicate_preserve_order(["a", "a", "b"]), eq=["a", "b"])
        tm.that(u.Ldif.deduplicate_preserve_order(["a", "a", "b"]), eq=["a", "b"])
        tm.that(u.normalize_ldif("VALUE"), eq="value")
        tm.that(u.Ldif.normalize_ldif("VALUE"), eq="value")

    @staticmethod
    def test_change_operation_remains_a_callable_model_type() -> None:
        """The type alias preserves normal runtime model construction."""
        operation: m.Ldif.ChangeOperation = m.Ldif.ChangeOperation(
            operation=c.Ldif.ChangeOperation.REPLACE,
            attribute="description",
            values=[],
        )
        tm.that(operation.attribute, eq="description")
        tm.that(operation.operation, eq=c.Ldif.ChangeOperation.REPLACE)
