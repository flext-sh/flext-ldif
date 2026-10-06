"""RFC 4512 Compliant Server Servers - Base LDAP Schema/ACL/Entry Implementation.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import ClassVar, Self, cast, overload, override

from flext_ldif import c, m, p, r, t, u
from flext_ldif.servers._base.mixins import FlextLdifServerMethodsMixin
from flext_ldif.servers._base.schema import FlextLdifServersBaseSchema
from flext_ldif.servers._rfc.schema_parse import FlextLdifServersRfcSchemaParseMixin
from flext_ldif.servers._rfc.schema_values import (
    FlextLdifServersRfcSchemaValuesMixin,
)
from flext_ldif.servers._rfc.schema_write import (
    FlextLdifServersRfcSchemaWriteMixin,
)
from flext_ldif.servers.base import FlextLdifServersBase


class FlextLdifServersRfcSchema(
    FlextLdifServersRfcSchemaValuesMixin,
    FlextLdifServersRfcSchemaWriteMixin,
    FlextLdifServersRfcSchemaParseMixin,
    FlextLdifServersBase.Schema,
):
    """RFC 4512 Compliant Schema Server - STRICT Implementation."""

    _module_logger: ClassVar[p.Logger] = u.fetch_logger(__name__)

    def __new__(
        cls,
        schema_service: p.Ldif.SchemaServer | None = None,
        parent_server: p.Ldif.SchemaServer | None = None,
        **kwargs: t.Ldif.Scalar | m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass,
    ) -> Self:
        """Override __new__ to support auto-execute and processor instantiation."""
        instance = object.__new__(cls)
        parent_server_raw = (
            parent_server if parent_server is not None else kwargs.get("_parent_server")
        )
        parent_server_value: p.Ldif.SchemaServer | None = (
            parent_server_raw
            if isinstance(parent_server_raw, p.Ldif.SchemaServer)
            else None
        )
        schema_instance: Self = instance
        super(FlextLdifServersBaseSchema, schema_instance).__init__()
        if schema_service is not None:
            object.__setattr__(schema_instance, "_schema_service", schema_service)
        if parent_server_value is not None:
            object.__setattr__(schema_instance, "_parent_server", parent_server_value)
        if cls.auto_execute:
            attr_def_raw = kwargs.get("attr_definition")
            attr_def: str | None = (
                attr_def_raw if isinstance(attr_def_raw, str) else None
            )
            oc_def_raw = kwargs.get("oc_definition")
            oc_def: str | None = oc_def_raw if isinstance(oc_def_raw, str) else None
            attr_mod_raw = kwargs.get("attr_model")
            attr_mod: m.Ldif.SchemaAttribute | None = (
                attr_mod_raw
                if isinstance(attr_mod_raw, m.Ldif.SchemaAttribute)
                else None
            )
            oc_mod_raw = kwargs.get("oc_model")
            oc_mod: m.Ldif.SchemaObjectClass | None = (
                oc_mod_raw if isinstance(oc_mod_raw, m.Ldif.SchemaObjectClass) else None
            )
            op_raw = kwargs.get("operation")
            op: str | None = (
                "parse" if isinstance(op_raw, str) and op_raw == "parse" else None
            )
            data: str | m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass | None = next(
                (
                    candidate
                    for candidate in (attr_def, oc_def, attr_mod, oc_mod)
                    if candidate is not None
                ),
                None,
            )
            schema_instance.execute(data=data, operation=op)
        return instance

    def __init__(
        self,
        schema_service: p.Ldif.SchemaServer | None = None,
        parent_server: p.Ldif.SchemaServer | None = None,
        **kwargs: t.Ldif.Scalar | m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass,
    ) -> None:
        """Initialize RFC schema server service."""
        self._init_base_schema(
            schema_service,
            parent_server,
            frozenset({
                "_parent_server",
                "_schema_service",
                "parent_server",
                "attr_definition",
                "oc_definition",
                "attr_model",
                "oc_model",
                "operation",
            }),
            **kwargs,
        )

    @overload
    def __call__(
        self,
        *,
        server: p.Ldif.ServerRegistry | None = None,
        settings: p.Ldif.Settings | None = None,
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
        builder_fields = FlextLdifServerMethodsMixin.builder_fields_or_none(
            fields,
            frozenset({"data", "operation"}),
            server,
            settings,
        )
        if builder_fields is not None:
            configured = super().__call__(
                server=server,
                settings=settings,
                **builder_fields,
            )
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
        return False

    @staticmethod
    def should_filter_out_objectclass(
        _objectclass: m.Ldif.SchemaObjectClass,
    ) -> bool:
        """RFC server does not filter objectClasses.

        Returns:
            The resulting ``bool``.
        """
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

        parse_result_raw = u.Ldif.parse(
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











