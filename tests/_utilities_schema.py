"""Schema and ACL parse/write assertion helpers for tests.

Focused utility module split out of ``tests.utilities``; the public surface is
re-exported through ``tests.utilities`` (see ``TestsSchemaAclAssertionsMixin``).

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import Annotated, ClassVar, Final

from flext_ldif import FlextLdifModels
from tests import t


class SchemaExpectations(FlextLdifModels.BaseModel):
    """Expected observable properties of one parsed schema definition.

    Carries the domain meaning "what the parsed schema node must look like";
    fields left as ``None`` are not asserted.
    """

    model_config: ClassVar[FlextLdifModels.ConfigDict] = FlextLdifModels.ConfigDict(
        frozen=True,
    )

    oid: Annotated[
        str | None,
        FlextLdifModels.Field(description="Expected parsed OID"),
    ] = None
    name: Annotated[
        str | None,
        FlextLdifModels.Field(description="Expected parsed NAME"),
    ] = None
    desc: Annotated[
        str | None,
        FlextLdifModels.Field(description="Expected parsed DESC"),
    ] = None
    syntax: Annotated[
        str | None,
        FlextLdifModels.Field(description="Expected attribute SYNTAX"),
    ] = None
    single_value: Annotated[
        bool | None,
        FlextLdifModels.Field(description="Expected attribute SINGLE-VALUE flag"),
    ] = None
    length: Annotated[
        int | None,
        FlextLdifModels.Field(description="Expected attribute syntax length"),
    ] = None
    kind: Annotated[
        str | None,
        FlextLdifModels.Field(description="Expected objectClass KIND"),
    ] = None
    sup: Annotated[
        str | None,
        FlextLdifModels.Field(description="Expected objectClass SUP"),
    ] = None
    must: Annotated[
        t.StrSequence | None,
        FlextLdifModels.Field(description="Expected objectClass MUST attributes"),
    ] = None
    may: Annotated[
        t.StrSequence | None,
        FlextLdifModels.Field(description="Expected objectClass MAY attributes"),
    ] = None


_PARSE_DISPATCH: Final[t.MappingKV[t.Tests.ParseMethod, str]] = {
    "parse_attribute": "parse_attribute",
    "parse_objectclass": "parse_objectclass",
    "parse_input": "parse_input",
}


def _assert_field_eq(
    value: object,
    field: str,
    expected: object,
    label: str,
) -> None:
    """Assert ``getattr(value, field) == expected`` with consistent diagnostic.

    Raises:
        AssertionError: If Expected.
    """
    if expected is None:
        return
    actual = getattr(value, field, None)
    if isinstance(expected, list) and actual is not None:
        if list(actual) != list(expected):
            msg = f"Expected {label} {expected}, got {actual}"
            raise AssertionError(msg)
        return
    if actual != expected:
        msg = f"Expected {label} '{expected}', got {actual}"
        raise AssertionError(msg)


def _assert_must_contain(serialized: str, must_contain: t.StrSequence) -> None:
    """Assert every fragment in ``must_contain`` appears in ``serialized``.

    Raises:
        AssertionError: If ``fragment not in serialized``.
    """
    for fragment in must_contain:
        if fragment not in serialized:
            msg = f"'{fragment}' not found in output: {serialized[:200]}..."
            raise AssertionError(msg)
