"""Behavioral tests for the public LDIF validation service APIs."""

from __future__ import annotations

import pytest
from flext_tests import tm

from tests import c, p, u

_INVALID_DESCRIPTORS: tuple[str, ...] = (
    "invalid name",
    "",
    " ",
    "has space",
)


class TestsFlextLdifValidationService:
    """Cover descriptor validation through the public facade only."""

    @pytest.mark.parametrize(
        "name",
        c.Tests.VALIDATION_VALID_OC_NAMES,
        ids=c.Tests.VALIDATION_VALID_OC_NAMES,
    )
    def test_validate_attribute_name_accepts_valid_descriptors(
        self,
        api: p.Ldif.Client,
        name: str,
    ) -> None:
        result = api.validate_attribute_name(name)
        is_valid = u.Tests.assert_success(result)

        tm.that(is_valid, eq=True)

    @pytest.mark.parametrize(
        "name",
        _INVALID_DESCRIPTORS,
        ids=("named", "empty", "space", "embedded-space"),
    )
    def test_validate_attribute_name_rejects_invalid_descriptors(
        self,
        api: p.Ldif.Client,
        name: str,
    ) -> None:
        result = api.validate_attribute_name(name)
        is_valid = u.Tests.assert_success(result)

        tm.that(is_valid, eq=False)

    @pytest.mark.parametrize(
        "name",
        c.Tests.VALIDATION_VALID_OC_NAMES,
        ids=c.Tests.VALIDATION_VALID_OC_NAMES,
    )
    def test_validate_objectclass_name_accepts_valid_descriptors(
        self,
        api: p.Ldif.Client,
        name: str,
    ) -> None:
        result = api.validate_objectclass_name(name)
        is_valid = u.Tests.assert_success(result)

        tm.that(is_valid, eq=True)

    @pytest.mark.parametrize(
        "name",
        _INVALID_DESCRIPTORS,
        ids=("named", "empty", "space", "embedded-space"),
    )
    def test_validate_objectclass_name_rejects_invalid_descriptors(
        self,
        api: p.Ldif.Client,
        name: str,
    ) -> None:
        result = api.validate_objectclass_name(name)
        is_valid = u.Tests.assert_success(result)

        tm.that(is_valid, eq=False)

    @pytest.mark.parametrize(
        "name",
        [*c.Tests.VALIDATION_VALID_OC_NAMES, *_INVALID_DESCRIPTORS],
    )
    def test_objectclass_validation_agrees_with_attribute_validation(
        self,
        api: p.Ldif.Client,
        name: str,
    ) -> None:
        """Both public descriptor checks share one RFC 4512 verdict."""
        attribute_verdict = u.Tests.assert_success(api.validate_attribute_name(name))
        objectclass_verdict = u.Tests.assert_success(
            api.validate_objectclass_name(name),
        )

        tm.that(objectclass_verdict, eq=attribute_verdict)

    @pytest.mark.parametrize(
        "name",
        [c.Tests.VALIDATION_VALID_OC_NAMES[0], c.Tests.VALIDATION_INVALID_DESCRIPTOR],
    )
    def test_validate_attribute_name_is_idempotent(
        self,
        api: p.Ldif.Client,
        name: str,
    ) -> None:
        """Repeated validation of the same descriptor is stable."""
        first = u.Tests.assert_success(api.validate_attribute_name(name))
        second = u.Tests.assert_success(api.validate_attribute_name(name))

        tm.that(second, eq=first)
