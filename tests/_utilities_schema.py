"""Schema and ACL parse/write assertion helpers for tests.

Focused utility module split out of ``tests.utilities``; the public surface is
re-exported through ``tests.utilities`` (see ``TestsSchemaAclAssertionsMixin``).

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Annotated, ClassVar, Final, overload

from flext_tests import tm

from flext_ldif import FlextLdifModels
from tests import c, m, p, t

if TYPE_CHECKING:
    from collections.abc import Callable


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


class TestsSchemaAclAssertionsMixin:
    """Parse/write assertion helpers for schema and ACL servers."""

    SchemaExpectations: ClassVar[type[SchemaExpectations]] = SchemaExpectations

    @staticmethod
    def _schema_definition_is_objectclass(schema_def: str) -> bool:
        """Whether the definition text declares an objectClass kind."""
        return any(
            kind in schema_def
            for kind in (
                c.Tests.SCHEMA_STRUCTURAL,
                c.Tests.SCHEMA_AUXILIARY,
                c.Tests.SCHEMA_ABSTRACT,
            )
        )

    @staticmethod
    def _parse_schema_definition(
        server: p.Ldif.SchemaServer,
        schema_def: str,
    ) -> m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass:
        """Parse one schema definition through the kind-matching server method.

        Returns:
            The resulting ``m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass``.
        """
        if TestsSchemaAclAssertionsMixin._schema_definition_is_objectclass(schema_def):
            value_raw = tm.ok(server.parse_objectclass(schema_def))
            value: m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass = (
                m.Ldif.SchemaObjectClass.model_validate(value_raw)
            )
            return value
        attribute_raw = tm.ok(server.parse_attribute(schema_def))
        attribute: m.Ldif.SchemaAttribute = m.Ldif.SchemaAttribute.model_validate(
            attribute_raw,
        )
        return attribute

    @staticmethod
    def _assert_common_expectations(
        value: m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass,
        expectations: SchemaExpectations,
    ) -> None:
        """Assert the OID/NAME/DESC fields shared by both schema kinds."""
        common_checks: tuple[tuple[str, object, str], ...] = (
            ("oid", expectations.oid, "OID"),
            ("name", expectations.name, "NAME"),
            ("desc", expectations.desc, "DESC"),
        )
        for field, expected, label in common_checks:
            _assert_field_eq(value, field, expected, label)

    @staticmethod
    def _assert_attribute_expectations(
        value: m.Ldif.SchemaAttribute,
        expectations: SchemaExpectations,
    ) -> None:
        """Assert the attribute-only SYNTAX/SINGLE-VALUE/length fields."""
        attr_checks: tuple[tuple[str, object, str], ...] = (
            ("syntax", expectations.syntax, "SYNTAX"),
            ("single_value", expectations.single_value, "SINGLE-VALUE"),
            ("length", expectations.length, "length"),
        )
        for field, expected, label in attr_checks:
            _assert_field_eq(value, field, expected, label)

    @staticmethod
    def _assert_objectclass_expectations(
        value: m.Ldif.SchemaObjectClass,
        expectations: SchemaExpectations,
    ) -> None:
        """Assert the objectClass-only KIND/SUP/MUST/MAY fields."""
        oc_checks: tuple[tuple[str, object, str], ...] = (
            ("kind", expectations.kind, "KIND"),
            ("sup", expectations.sup, "SUP"),
            (
                "must",
                list(expectations.must) if expectations.must is not None else None,
                "MUST",
            ),
            (
                "may",
                list(expectations.may) if expectations.may is not None else None,
                "MAY",
            ),
        )
        for field, expected, label in oc_checks:
            _assert_field_eq(value, field, expected, label)

    @classmethod
    def assert_server_schema_parse_and_properties(
        cls,
        server: p.Ldif.SchemaServer,
        schema_def: str,
        *,
        expectations: SchemaExpectations,
    ) -> m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass:
        """Parse schema content and assert the expected properties.

        Returns:
            The resulting ``m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass``.
        """
        value = cls._parse_schema_definition(server, schema_def)
        cls._assert_common_expectations(value, expectations)
        if isinstance(value, m.Ldif.SchemaAttribute):
            cls._assert_attribute_expectations(value, expectations)
        else:
            cls._assert_objectclass_expectations(value, expectations)
        return value

    @overload
    @staticmethod
    def server_parse_and_unwrap[
        SchemaNodeT: (m.Ldif.SchemaAttribute, m.Ldif.SchemaObjectClass, m.Ldif.Acl),
    ](
        server: p.Ldif.SchemaServer | p.Tests.ParseInputServer,
        content: str,
        parse_method: t.Tests.ParseMethod = ...,
        expected_type: type[SchemaNodeT] = ...,
        should_succeed: bool | None = ...,
    ) -> SchemaNodeT | None: ...
    @overload
    @staticmethod
    def server_parse_and_unwrap(
        server: p.Ldif.SchemaServer | p.Tests.ParseInputServer,
        content: str,
        parse_method: t.Tests.ParseMethod = ...,
        expected_type: None = ...,
        should_succeed: bool | None = ...,
    ) -> m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass | m.Ldif.Acl | None: ...
    @staticmethod
    def server_parse_and_unwrap[
        SchemaNodeT: (m.Ldif.SchemaAttribute, m.Ldif.SchemaObjectClass, m.Ldif.Acl),
    ](
        server: p.Ldif.SchemaServer | p.Tests.ParseInputServer,
        content: str,
        parse_method: t.Tests.ParseMethod = "parse_server",
        expected_type: type[SchemaNodeT] | None = None,
        should_succeed: bool | None = None,
    ) -> m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass | m.Ldif.Acl | None:
        """Parse content with a server and unwrap the typed result.

        Returns:
            The resulting ``m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass |
                m.Ldif.Acl | None``.

        Raises:
            AssertionError: If ``method_name is None or not isinstance(server,
                p.Ldif.SchemaServer)``; or if ``result.failure``; or if Expected; or
                if ``result.success``.
        """
        method_name = _PARSE_DISPATCH.get(parse_method)
        if method_name is None or not isinstance(server, p.Ldif.SchemaServer):
            msg = f"{parse_method} is not supported by this server"
            raise AssertionError(msg)
        method: Callable[
            [str],
            p.Result[
                m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass | m.Ldif.Acl
            ],
        ] = getattr(server, method_name)
        result = method(content)
        if should_succeed is False:
            if result.success:
                raise AssertionError("Expected failure but parse succeeded")
            return None
        if result.failure:
            raise AssertionError(
                f"Expected success but parse failed: {result.error}",
            )
        value = result.value
        if expected_type is not None and not isinstance(value, expected_type):
            msg_0 = f"Expected {expected_type.__name__}, got {type(value).__name__}"
            raise AssertionError(msg_0)
        # `method` is typed to return exactly these three models, so the
        # isinstance narrowing above is total and no fallthrough exists.
        return value

    @staticmethod
    def acl_parse_and_unwrap(
        server: p.Tests.ParseAclServer,
        content: str,
        expected_type: type[m.Ldif.Acl] | None = None,
        should_succeed: bool | None = None,
        message: str | None = None,
    ) -> m.Ldif.Acl | None:
        """Parse ACL content and unwrap the resulting model.

        Returns:
            The resulting ``m.Ldif.Acl | None``.

        Raises:
            AssertionError: If ``result.failure``; or if Expected; or if
                ``result.success``.
        """
        result = server.parse_server(content)
        if should_succeed is False:
            if result.success:
                raise AssertionError(
                    message or "Expected failure but parse succeeded",
                )
            return None
        if result.failure:
            raise AssertionError(
                message or f"Expected success but parse failed: {result.error}",
            )
        value: m.Ldif.Acl = result.unwrap()
        if expected_type is not None and not isinstance(value, expected_type):
            msg = f"Expected {expected_type.__name__}, got {type(value).__name__}"
            raise AssertionError(msg)
        return value

    @staticmethod
    def server_write_and_unwrap(
        server: p.Tests.WriteAttributeServer
        | p.Tests.WriteObjectClassServer
        | p.Tests.WriteAclServer,
        data: m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass | m.Ldif.Acl,
        write_method: t.Tests.WriteMethod = "write",
        must_contain: t.StrSequence | None = None,
        message: str | None = None,
    ) -> str:
        """Write content with a server and unwrap the serialized output.

        Returns:
            The resulting ``str``.

        Raises:
            AssertionError: If ``entry is None``; or if ``result.failure``.
            TypeError: If ``not isinstance(server, server_proto)``; or if ``not
                isinstance(data, data_cls)``.
        """
        dispatch: t.MappingKV[
            t.Tests.WriteMethod,
            tuple[type, type[m.BaseModel]],
        ] = {
            "_write_attribute": (
                p.Tests.WriteAttributeServer,
                m.Ldif.SchemaAttribute,
            ),
            "_write_objectclass": (
                p.Tests.WriteObjectClassServer,
                m.Ldif.SchemaObjectClass,
            ),
            "_write_acl": (p.Tests.WriteAclServer, m.Ldif.Acl),
        }
        entry = dispatch.get(write_method)
        if entry is None:
            msg = f"{write_method} is not supported by this server"
            raise AssertionError(msg)
        # Why: widen from the dict's per-key literal tuple type so the
        # isinstance guards below stay a real runtime check (write_method
        # is caller-supplied and can mismatch server/data at runtime)
        # rather than a statically-tautological one (pyright
        # reportUnnecessaryIsInstance).
        server_proto: type
        data_cls: type
        server_proto, data_cls = entry
        if not isinstance(server, server_proto):
            msg = f"{write_method} is not supported by this server"
            raise TypeError(msg)
        if not isinstance(data, data_cls):
            msg = f"{write_method} requires a {data_cls.__name__}"
            raise TypeError(msg)
        method: Callable[[m.BaseModel], p.Result[str]] = getattr(
            server,
            write_method,
        )
        result = method(data)
        if result.failure:
            raise AssertionError(message or f"Write failed: {result.error}")
        serialized: str = result.unwrap()
        if must_contain is not None:
            _assert_must_contain(serialized, must_contain)
        return serialized

    @staticmethod
    def acl_write_and_unwrap(
        server: p.Tests.WriteAclContentServer,
        data: m.Ldif.Acl,
        must_contain: t.StrSequence | None = None,
        message: str | None = None,
    ) -> str:
        """Write ACL content and unwrap the serialized output.

        Returns:
            The resulting ``str``.

        Raises:
            AssertionError: If ``result.failure``.
        """
        result = server.write(data)
        if result.failure:
            raise AssertionError(message or f"Write failed: {result.error}")
        serialized: str = result.unwrap()
        if must_contain is not None:
            _assert_must_contain(serialized, must_contain)
        return serialized
