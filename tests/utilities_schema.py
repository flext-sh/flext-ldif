"""Schema and ACL parse/write assertion helpers for tests.

Focused utility module split out of ``tests.utilities``; the public surface is
re-exported through ``tests.utilities`` (see ``TestsSchemaAclAssertionsMixin``).

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Annotated, ClassVar, Final, cast

from flext_ldif import FlextLdifModels
from tests import c, m, p, t, tm

if TYPE_CHECKING:
    from collections.abc import Callable


class TestsFlextLdifSchemaExpectations(FlextLdifModels.BaseModel):
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


PARSE_DISPATCH: Final[t.MappingKV[t.Tests.ParseMethod, str]] = {
    "parse_attribute": "parse_attribute",
    "parse_objectclass": "parse_objectclass",
    "parse_input": "parse_input",
}


def assert_field_eq(
    value: FlextLdifModels.BaseModel,
    field: str,
    expected: t.JsonValue,
    label: str,
) -> None:
    """Assert ``getattr(value, field) == expected`` with consistent diagnostic.

    Args:
        value: Model carrying the field under assertion.
        field: Field name to compare.
        expected: Expected value; None skips the assertion.
        label: Human-readable field label used in the failure message.

    Raises:
        AssertionError: If the actual value differs from the expected value.

    """
    if expected is None:
        return
    actual = getattr(value, field, None)
    if isinstance(expected, list) and actual is not None:
        expected_items = cast("list[object]", expected)
        if list(actual) != expected_items:
            msg = f"Expected {label} {expected}, got {actual}"
            raise AssertionError(msg)
        return
    if actual != expected:
        msg = f"Expected {label} '{expected}', got {actual}"
        raise AssertionError(msg)


def assert_must_contain(serialized: str, must_contain: t.StrSequence) -> None:
    """Assert every fragment in ``must_contain`` appears in ``serialized``.

    Args:
        serialized: Serialized output text to inspect.
        must_contain: Fragments required to be present.

    Raises:
        AssertionError: If a fragment is missing from the serialized output.

    """
    for fragment in must_contain:
        if fragment not in serialized:
            msg = f"'{fragment}' not found in output: {serialized[:200]}..."
            raise AssertionError(msg)


class TestsSchemaAclAssertionsMixin:
    """Parse/write assertion helpers for schema and ACL servers."""

    @staticmethod
    def _schema_definition_is_objectclass(schema_def: str) -> bool:
        """Whether the definition text declares an objectClass kind.

        Returns:
            True when the definition text declares an objectClass kind.

        """
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

        Args:
            server: Schema server that parses the definition.
            schema_def: Raw schema definition text.

        Returns:
            The parsed attribute or objectClass.

        """
        is_objectclass = TestsSchemaAclAssertionsMixin._schema_definition_is_objectclass
        if is_objectclass(schema_def):
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
        expectations: TestsFlextLdifSchemaExpectations,
    ) -> None:
        """Assert the OID/NAME/DESC fields shared by both schema kinds."""
        common_checks: tuple[tuple[str, t.JsonValue, str], ...] = (
            ("oid", expectations.oid, "OID"),
            ("name", expectations.name, "NAME"),
            ("desc", expectations.desc, "DESC"),
        )
        for field, expected, label in common_checks:
            assert_field_eq(value, field, expected, label)

    @staticmethod
    def _assert_attribute_expectations(
        value: m.Ldif.SchemaAttribute,
        expectations: TestsFlextLdifSchemaExpectations,
    ) -> None:
        """Assert the attribute-only SYNTAX/SINGLE-VALUE/length fields."""
        attr_checks: tuple[tuple[str, t.JsonValue, str], ...] = (
            ("syntax", expectations.syntax, "SYNTAX"),
            ("single_value", expectations.single_value, "SINGLE-VALUE"),
            ("length", expectations.length, "length"),
        )
        for field, expected, label in attr_checks:
            assert_field_eq(value, field, expected, label)

    @staticmethod
    def _assert_objectclass_expectations(
        value: m.Ldif.SchemaObjectClass,
        expectations: TestsFlextLdifSchemaExpectations,
    ) -> None:
        """Assert the objectClass-only KIND/SUP/MUST/MAY fields."""
        oc_checks: tuple[tuple[str, t.JsonValue, str], ...] = (
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
            assert_field_eq(value, field, expected, label)

    @classmethod
    def assert_server_schema_parse_and_properties(
        cls,
        server: p.Ldif.SchemaServer,
        schema_def: str,
        *,
        expectations: TestsFlextLdifSchemaExpectations,
    ) -> m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass:
        """Parse schema content and assert the expected properties.

        Args:
            server: Schema server that parses the definition.
            schema_def: Raw schema definition text.
            expectations: Expected observable properties of the parse.

        Returns:
            The parsed attribute or objectClass.

        """
        value = cls._parse_schema_definition(server, schema_def)
        cls._assert_common_expectations(value, expectations)
        if isinstance(value, m.Ldif.SchemaAttribute):
            cls._assert_attribute_expectations(value, expectations)
        else:
            cls._assert_objectclass_expectations(value, expectations)
        return value

    @staticmethod
    def server_parse_and_unwrap[
        SchemaNodeT: (m.Ldif.SchemaAttribute, m.Ldif.SchemaObjectClass, m.Ldif.Acl),
    ](
        server: p.Ldif.SchemaServer | p.Tests.ParseInputServer,
        content: str,
        parse_method: t.Tests.ParseMethod = "parse_server",
        *,
        expected_type: type[SchemaNodeT],
        should_succeed: bool | None = None,
    ) -> SchemaNodeT | None:
        """Parse content with a server and unwrap the typed result.

        Args:
            server: Server that parses the content.
            content: Raw content text.
            parse_method: Name of the parse entrypoint to dispatch.
            expected_type: Expected type of the parsed value.
            should_succeed: When False, the parse is expected to fail.

        Returns:
            The parsed value, or None when failure was expected.

        Raises:
            AssertionError: If the parse method is unsupported, the parse
                outcome contradicts ``should_succeed``, or the parse fails.
            TypeError: If the parsed value does not match ``expected_type``.

        """
        method_name = PARSE_DISPATCH.get(parse_method)
        if method_name is None or not isinstance(server, p.Ldif.SchemaServer):
            msg = f"{parse_method} is not supported by this server"
            raise AssertionError(msg)
        method: Callable[
            [str],
            p.Result[m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass | m.Ldif.Acl],
        ] = getattr(server, method_name)
        result = method(content)
        if should_succeed is False:
            if result.success:
                msg_0 = "Expected failure but parse succeeded"
                raise AssertionError(msg_0)
            return None
        if result.failure:
            msg_0 = f"Expected success but parse failed: {result.error}"
            raise AssertionError(
                msg_0,
            )
        value = result.value
        if not isinstance(value, expected_type):
            msg_0 = f"Expected {expected_type.__name__}, got {type(value).__name__}"
            raise TypeError(msg_0)
        # `method` is typed to return exactly these three models, so the
        # isinstance narrowing above is total and no fallthrough exists.
        return value

    @staticmethod
    def acl_parse_and_unwrap(
        server: p.Tests.ParseAclServer,
        content: str,
        expected_type: type[m.Ldif.Acl] | None = None,
        *,
        should_succeed: bool | None = None,
        message: str | None = None,
    ) -> m.Ldif.Acl | None:
        """Parse ACL content and unwrap the resulting model.

        Args:
            server: ACL server that parses the content.
            content: Raw ACL content text.
            expected_type: Expected type of the parsed ACL; None skips the
                type assertion.
            should_succeed: When False, the parse is expected to fail.
            message: Optional failure message override.

        Returns:
            The parsed ACL, or None when failure was expected.

        Raises:
            AssertionError: If the parse outcome contradicts
                ``should_succeed``, the parse fails, or the value type
                mismatches ``expected_type``.

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

        Args:
            server: Server that serializes the data.
            data: Schema or ACL model to write.
            write_method: Name of the write entrypoint to dispatch.
            must_contain: Fragments required in the serialized output.
            message: Optional failure message override.

        Returns:
            The serialized output text.

        Raises:
            AssertionError: If the write method is unsupported or the write
                fails.
            TypeError: If the server or data does not match the write
                method's contract.

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
            assert_must_contain(serialized, must_contain)
        return serialized

    @staticmethod
    def acl_write_and_unwrap(
        server: p.Tests.WriteAclContentServer,
        data: m.Ldif.Acl,
        must_contain: t.StrSequence | None = None,
        message: str | None = None,
    ) -> str:
        """Write ACL content and unwrap the serialized output.

        Args:
            server: ACL server that serializes the data.
            data: ACL model to write.
            must_contain: Fragments required in the serialized output.
            message: Optional failure message override.

        Returns:
            The serialized output text.

        Raises:
            AssertionError: If the write fails.

        """
        result = server.write(data)
        if result.failure:
            raise AssertionError(message or f"Write failed: {result.error}")
        serialized: str = result.unwrap()
        if must_contain is not None:
            assert_must_contain(serialized, must_contain)
        return serialized

    # Re-exported last so the class attribute never shadows the module-level
    # type for the annotations above (mypy: variable-not-a-type).
    SchemaExpectations: ClassVar[type[TestsFlextLdifSchemaExpectations]] = (
        TestsFlextLdifSchemaExpectations
    )


__all__: list[str] = [
    "PARSE_DISPATCH",
    "TestsFlextLdifSchemaExpectations",
    "TestsSchemaAclAssertionsMixin",
    "assert_field_eq",
    "assert_must_contain",
]
