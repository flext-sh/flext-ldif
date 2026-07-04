"""Behavioral tests for the public LDIF validation service APIs."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
from flext_tests import tm

from tests.constants import c
from tests.utilities import u

if TYPE_CHECKING:
    from tests.protocols import p


class TestsFlextLdifValidationService:
    """Cover descriptor validation through the public facade only."""

    @pytest.mark.parametrize(
        "name",
        c.Tests.VALIDATION_VALID_OC_NAMES,
        ids=c.Tests.VALIDATION_VALID_OC_NAMES,
    )
    def test_validate_attribute_name_accepts_valid_descriptors(
        self,
        api: p.Ldif.LdifClient,
        name: str,
    ) -> None:
        result = api.validate_attribute_name(name)
        is_valid = u.Tests.assert_success(result)

        tm.that(is_valid, eq=True)

    def test_validate_attribute_name_rejects_invalid_descriptor(
        self,
        api: p.Ldif.LdifClient,
    ) -> None:
        result = api.validate_attribute_name(c.Tests.VALIDATION_INVALID_DESCRIPTOR)
        is_valid = u.Tests.assert_success(result)

        tm.that(is_valid, eq=False)

    @pytest.mark.parametrize(
        "name",
        c.Tests.VALIDATION_VALID_OC_NAMES,
        ids=c.Tests.VALIDATION_VALID_OC_NAMES,
    )
    def test_validate_objectclass_name_accepts_valid_descriptors(
        self,
        api: p.Ldif.LdifClient,
        name: str,
    ) -> None:
        result = api.validate_objectclass_name(name)
        is_valid = u.Tests.assert_success(result)

        tm.that(is_valid, eq=True)

    def test_validate_objectclass_name_rejects_invalid_descriptor(
        self,
        api: p.Ldif.LdifClient,
    ) -> None:
        result = api.validate_objectclass_name(c.Tests.VALIDATION_INVALID_DESCRIPTOR)
        is_valid = u.Tests.assert_success(result)

        tm.that(is_valid, eq=False)
