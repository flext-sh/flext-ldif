"""RFC 4512 Compliant Server Servers - Base LDAP Schema/ACL/Entry Implementation.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import ClassVar, Self, cast, overload, override

from flext_ldif import c, m, p, r, t, u
from flext_ldif.servers import FlextLdifServersBase
from flext_ldif.servers._base import (
    FlextLdifServerMethodsMixin,
    FlextLdifServersBaseSchema,
)
from flext_ldif.servers._rfc import (
    FlextLdifServersRfcSchemaParseMixin,
    FlextLdifServersRfcSchemaValuesMixin,
    FlextLdifServersRfcSchemaWriteMixin,
)


class FlextLdifServersRfcSchema(
    FlextLdifServersRfcSchemaWriteMixin,
    FlextLdifServersRfcSchemaParseMixin,
    FlextLdifServersRfcSchemaValuesMixin,
    FlextLdifServersBase,
):
    """RFC 4512 Compliant Schema Server - STRICT Implementation."""

    _module_logger: ClassVar[p.Logger] = u.fetch_logger(__name__)

    @overload
    def __call__(
        self,
        *,
        server: p.Ldif.ServerRegistry | None = None,
        settings: p.Ldif.Settings | None = None,
        registry: p.Registry | None = None,
        **fields: t.JsonValue,
    ) -> Self: ...

    @overload
    def __call__(
        self,
        data: str,
        *,
        operation: str | None = None,
    ) -> str | m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass: ...

    @overload
    def __call__(
        self,
        data: m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass,
        operation: str | None = None,
    ) -> str: ...

    @overload
    def __call__(
        self,
        data: None = None,
        *,
        operation: str | None = None,
    ) -> str | m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass: ...

    def __call__(
        self,
        data: t.JsonValue
        | m.Ldif.SchemaAttribute
        | m.Ldif.SchemaObjectClass
        | None = None,
        operation: t.JsonValue | None = None,
        server: p.Ldif.ServerRegistry | None = None,
        settings: p.Ldif.Settings | None = None,
        registry: p.Registry | None = None,
        **fields: t.JsonValue,
    ) -> Self | m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass | str:
        """Callable interface - automatic polymorphic processor.

        Returns:
            The resulting ``Self | m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass |
                str``.

        Raises:
            TypeError: If RFC schema operation returned unsupported value.
            ValueError: If ``result.failure``.

        """
        if registry is not None:
            return self.configure_runtime(
                server=server, settings=settings, registry=registry, **fields
            )
        configured = FlextLdifServerMethodsMixin.dispatch_builder(
            super().__call__,
            fields,
            frozenset({"data", c.ContextScope.OPERATION}),
            server,
            settings,
        )
        if configured is not None:
            return cast("Self", configured)
        narrowed_data = (
            data
            if isinstance(data, (str, m.Ldif.SchemaAttribute, m.Ldif.SchemaObjectClass))
            or data is None
            else None
        )
        narrowed_operation = self._narrow_operation(operation)
        result = self.execute(data=narrowed_data, operation=narrowed_operation)
        if result.failure:
            msg = result.error or "RFC schema operation failed"
            raise ValueError(msg)
        value = result.value
        if isinstance(value, (str, m.Ldif.SchemaAttribute, m.Ldif.SchemaObjectClass)):
            return value
        msg = "RFC schema operation returned unsupported value"
        raise TypeError(msg)

    @override
    def can_handle_attribute(
        self,
        attr_definition: str | m.Ldif.SchemaAttribute,
    ) -> bool:
        """Check if RFC server can handle attribute definitions (abstract impl).

        Returns:
            The resulting ``bool``.

        """
        del attr_definition
        return True

    @override
    def can_handle_objectclass(
        self,
        oc_definition: str | m.Ldif.SchemaObjectClass,
    ) -> bool:
        """Check if RFC server can handle objectClass definitions (abstract impl).

        Returns:
            The resulting ``bool``.

        """
        del oc_definition
        return True

    def create_metadata(
        self,
        original_format: str,
        extensions: t.Ldif.MetadataInputMapping | None = None,
    ) -> m.Ldif.ServerMetadata:
        """Create server metadata with consistent server-specific extensions.

        Returns:
            The resulting ``m.Ldif.ServerMetadata``.

        """
        server_type_value = self._get_server_type()
        all_extensions: t.MutableJsonMapping = {}
        all_extensions[c.Ldif.ACL_ORIGINAL_FORMAT] = original_format
        if extensions:
            all_extensions.update(extensions)
        return m.Ldif.ServerMetadata(
            server_type=server_type_value,
            extensions=all_extensions,
        )

    @staticmethod
    def should_filter_out_attribute(_attribute: m.Ldif.SchemaAttribute) -> bool:
        """RFC server does not filter attributes.

        Returns:
            The resulting ``bool``.

        """
        del _attribute
        return False

    @staticmethod
    def should_filter_out_objectclass(
        _objectclass: m.Ldif.SchemaObjectClass,
    ) -> bool:
        """RFC server does not filter objectClasses.

        Returns:
            The resulting ``bool``.

        """
        del _objectclass
        return False

    @override
    def _hook_post_parse_attribute(
        self,
        attr: m.Ldif.SchemaAttribute,
    ) -> p.Result[m.Ldif.SchemaAttribute]:
        """Run hook after parsing an attribute definition.

        Returns:
            The resulting ``p.Result[m.Ldif.SchemaAttribute]``.

        """
        return r[m.Ldif.SchemaAttribute].ok(attr)

    @override
    def _parse_attribute(
        self,
        attr_definition: str,
    ) -> p.Result[m.Ldif.SchemaAttribute]:
        """Parse RFC 4512 attribute definition using generalized parser.

        Returns:
            The resulting ``p.Result[m.Ldif.SchemaAttribute]``.

        """
        server_type = self._get_server_type()

        def parse_parts_hook(
            definition: str,
        ) -> p.Result[t.Ldif.MutableMetadataMapping]:
            parsed: p.Result[t.Ldif.MutableMetadataMapping] = u.Ldif.parse_attribute(
                definition,
            )
            return parsed

        parse_result_raw = u.Ldif.parse_definition(
            definition=attr_definition,
            server_type=server_type,
            parse_parts_hook=parse_parts_hook,
        )
        if parse_result_raw.failure:
            return r[m.Ldif.SchemaAttribute].from_failure(parse_result_raw)
        parsed_raw = parse_result_raw.value
        parsed: t.Ldif.MutableMetadataMapping = dict(parsed_raw)
        syntax = parsed.get("syntax")
        syntax_str = str(syntax) if syntax is not None else None
        syntax_validation_error = self._extract_syntax_validation_error(
            parsed.get("syntax_validation"),
        )
        metadata = FlextLdifServersBaseSchema.build_attribute_metadata(
            attr_definition,
            syntax_str,
            syntax_validation_error,
            parsed,
            server_type=server_type,
        )
        attr_name = self._to_optional_str(parsed.get("name"))
        if attr_name is None:
            attr_name = self._to_required_value(parsed.get("oid"))
        attr_model = m.Ldif.SchemaAttribute(
            oid=self._to_required_value(parsed.get("oid")),
            name=attr_name,
            desc=self._to_optional_str(parsed.get("desc")),
            equality=self._to_optional_str(parsed.get("equality")),
            ordering=self._to_optional_str(parsed.get("ordering")),
            substr=self._to_optional_str(parsed.get("substr")),
            syntax=self._to_optional_str(parsed.get("syntax")),
            length=self._to_optional_int(parsed.get("length")),
            single_value=bool(parsed.get("single_value")),
            no_user_modification=bool(parsed.get("no_user_modification")),
            usage=self._to_optional_str(parsed.get("usage")),
            sup=self._to_optional_str(parsed.get("sup")),
            metadata=metadata,
        )
        return self._hook_post_parse_attribute(attr_model)

    @override
    def _parse_objectclass(
        self,
        oc_definition: str,
    ) -> p.Result[m.Ldif.SchemaObjectClass]:
        """Parse RFC 4512 objectClass definition using core parser.

        Returns:
            The resulting ``p.Result[m.Ldif.SchemaObjectClass]``.

        """
        parse_result = self._parse_objectclass_core(oc_definition)
        if parse_result.failure:
            return parse_result
        return self._hook_post_parse_objectclass(parse_result.value)


__all__: list[str] = ["FlextLdifServersRfcSchema"]
