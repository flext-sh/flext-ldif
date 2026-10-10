"""Behavioral tests for the public LDIF validation service APIs.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from tests import c, tm, u

if TYPE_CHECKING:
    from collections.abc import Callable

    from tests import p, t

_INVALID_DESCRIPTORS: t.VariadicTuple[str] = ("invalid name", "", " ", "has space")


def _assert_descriptor(
    validate: Callable[[str], p.Result[bool]],
    name: str,
    *,
    is_valid: bool,
) -> None:
    """Assert one public descriptor check returns the expected verdict."""
    result = validate(name)
    is_valid_result = u.Tests.assert_success(result)

    tm.that(is_valid_result, eq=is_valid)


class TestsFlextLdifValidationService:
    """Cover descriptor validation through the public facade only."""

    @staticmethod
    @pytest.mark.parametrize(
        "name",
        c.Tests.VALIDATION_VALID_OC_NAMES,
        ids=c.Tests.VALIDATION_VALID_OC_NAMES,
    )
    def test_validate_attribute_name_accepts_valid_descriptors(
        api: p.Ldif.LdifClient,
        name: str,
    ) -> None:
        """Test validate attribute name accepts valid descriptors."""
        _assert_descriptor(api.validate_attribute_name, name, is_valid=True)

    @staticmethod
    @pytest.mark.parametrize(
        "name",
        _INVALID_DESCRIPTORS,
        ids=("named", "empty", "space", "embedded-space"),
    )
    def test_validate_attribute_name_rejects_invalid_descriptors(
        api: p.Ldif.LdifClient,
        name: str,
    ) -> None:
        """Test validate attribute name rejects invalid descriptors."""
        _assert_descriptor(api.validate_attribute_name, name, is_valid=False)

    @staticmethod
    @pytest.mark.parametrize(
        "name",
        c.Tests.VALIDATION_VALID_OC_NAMES,
        ids=c.Tests.VALIDATION_VALID_OC_NAMES,
    )
    def test_validate_objectclass_name_accepts_valid_descriptors(
        api: p.Ldif.LdifClient,
        name: str,
    ) -> None:
        """Test validate objectclass name accepts valid descriptors."""
        _assert_descriptor(api.validate_objectclass_name, name, is_valid=True)

    @staticmethod
    @pytest.mark.parametrize(
        "name",
        _INVALID_DESCRIPTORS,
        ids=("named", "empty", "space", "embedded-space"),
    )
    def test_validate_objectclass_name_rejects_invalid_descriptors(
        api: p.Ldif.LdifClient,
        name: str,
    ) -> None:
        """Test validate objectclass name rejects invalid descriptors."""
        _assert_descriptor(api.validate_objectclass_name, name, is_valid=False)

    @staticmethod
    @pytest.mark.parametrize(
        "name",
        [*c.Tests.VALIDATION_VALID_OC_NAMES, *_INVALID_DESCRIPTORS],
    )
    def test_objectclass_validation_agrees_with_attribute_validation(
        api: p.Ldif.LdifClient,
        name: str,
    ) -> None:
        """Both public descriptor checks share one RFC 4512 verdict."""
        attribute_verdict = u.Tests.assert_success(api.validate_attribute_name(name))
        objectclass_verdict = u.Tests.assert_success(
            api.validate_objectclass_name(name),
        )

        tm.that(objectclass_verdict, eq=attribute_verdict)

    @staticmethod
    @pytest.mark.parametrize(
        "name",
        [c.Tests.VALIDATION_VALID_OC_NAMES[0], c.Tests.VALIDATION_INVALID_DESCRIPTOR],
    )
    def test_validate_attribute_name_is_idempotent(
        api: p.Ldif.LdifClient,
        name: str,
    ) -> None:
        """Repeated validation of the same descriptor is stable."""
        first = u.Tests.assert_success(api.validate_attribute_name(name))
        second = u.Tests.assert_success(api.validate_attribute_name(name))

        tm.that(second, eq=first)
