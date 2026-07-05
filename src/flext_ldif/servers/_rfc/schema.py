"""RFC 4512 Compliant Server Servers - Base LDAP Schema/ACL/Entry Implementation."""

from __future__ import annotations

from collections.abc import (
    Mapping,
    MutableMapping,
    Sequence,
)
from typing import ClassVar, Self, overload, override

from flext_ldif import c, m, p, r, t, u
from flext_ldif.servers._base.mixins import FlextLdifServerMethodsMixin
from flext_ldif.servers._base.schema import FlextLdifServersBaseSchema


class FlextLdifServersRfcSchema(FlextLdifServersBaseSchema):
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
        filtered_kwargs: dict[str, t.Primitives | None] = {}
        excluded_keys = {
            "_parent_server",
            "parent_server",
            "_schema_service",
            "attr_definition",
            "oc_definition",
            "attr_model",
            "oc_model",
            "operation",
        }
        for key, value in kwargs.items():
            if key in excluded_keys:
                continue
            if isinstance(value, t.PRIMITIVES_TYPES):
                filtered_kwargs[key] = value
        schema_service_typed: p.Ldif.SchemaServer | None = schema_service
        FlextLdifServersBaseSchema.__init__(
            self,
            _schema_service=schema_service_typed,
            _parent_server=None,
            **filtered_kwargs,
        )
        if parent_server is not None:
            object.__setattr__(self, "_parent_server", parent_server)

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
        data: m.Ldif.SchemaAttribute,
        operation: str | None = None,
    ) -> str: ...

    @overload
    def __call__(
        self,
        data: m.Ldif.SchemaObjectClass,
        operation: str | None = None,
    ) -> str: ...

    @overload
    def __call__(
        self,
        data: str | m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass | None = None,
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
        *,
        server: p.Ldif.ServerRegistry | None = None,
        settings: p.Ldif.Settings | None = None,
        **fields: t.JsonValue,
    ) -> Self | str | m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass:
        """Callable interface - automatic polymorphic processor."""
        builder_fields = FlextLdifServerMethodsMixin.project_processor_fields(
            fields,
            frozenset({"data", "operation"}),
            force_dispatch=server is not None or settings is not None,
        )
        if builder_fields is not None:
            configured: Self = super().__call__(
                server=server,
                settings=settings,
                **builder_fields,
            )
            return configured
        narrowed_data = (
            data
            if isinstance(
                data,
                (str, m.Ldif.SchemaAttribute, m.Ldif.SchemaObjectClass),
            )
            or data is None
            else None
        )
        narrowed_operation = operation if isinstance(operation, str) else None
        result = self.execute(data=narrowed_data, operation=narrowed_operation)
        if result.failure:
            msg = result.error or "RFC schema operation failed"
            raise ValueError(msg)
        value = result.value
        if isinstance(value, (str, m.Ldif.SchemaAttribute, m.Ldif.SchemaObjectClass)):
            return value
        msg = "RFC schema operation returned unsupported value"
        raise TypeError(msg)

    @classmethod
    def _extract_syntax_validation_error(
        cls,
        value: t.JsonValue | None,
    ) -> str | None:
        syntax_validation = cls._coerce_dynamic_metadata(value)
        syntax_error = syntax_validation.get("syntax_validation_error")
        return syntax_error if isinstance(syntax_error, str) else None

    @classmethod
    def _to_optional_str_or_list(
        cls,
        value: t.JsonValue | None,
    ) -> str | t.MutableSequenceOf[str] | None:
        if isinstance(value, str):
            return value
        return cls._to_string_list(value)

    @staticmethod
    def _coerce_dynamic_metadata(
        value: t.JsonValue | None,
    ) -> m.Ldif.DynamicMetadata:
        json_value: t.JsonPayload | m.Ldif.DynamicMetadata | None = value
        if isinstance(json_value, m.Ldif.DynamicMetadata):
            return json_value
        if json_value is None:
            return m.Ldif.DynamicMetadata()
        try:
            validated: m.Ldif.DynamicMetadata = m.Ldif.DynamicMetadata.model_validate(
                json_value,
            )
            return validated
        except c.ValidationError:
            return m.Ldif.DynamicMetadata()

    @staticmethod
    def _convert_extensions_for_server(
        metadata: m.Ldif.DynamicMetadata,
    ) -> t.Ldif.SchemaExtensionsMapping:
        extensions: t.Ldif.SchemaExtensionsMapping = {}
        for key, value in metadata.items():
            json_value: t.JsonPayload | None = value
            if isinstance(json_value, list):
                list_value: t.MutableSequenceOf[str] = [
                    str(item) for item in json_value
                ]
                extensions[key] = list_value
            elif isinstance(json_value, (bool, str)):
                extensions[key] = json_value
            else:
                extensions[key] = str(u.normalize_to_json_value(json_value))
        return extensions

    @staticmethod
    def _to_optional_int(value: t.JsonValue | None) -> int | None:
        json_value: t.JsonPayload | None = value
        if isinstance(json_value, int):
            return json_value
        if json_value is None or not json_value:
            return None
        if isinstance(json_value, Mapping) or (
            isinstance(json_value, Sequence) and not isinstance(json_value, str | bytes)
        ):
            return None
        parsed = FlextLdifServersRfcSchema._parse_int(json_value)
        if parsed.success:
            parsed_value: int = parsed.value
            return parsed_value
        return None

    @staticmethod
    def _parse_int(json_value: t.JsonPayload) -> p.Result[int]:
        """Parse a JSON scalar into an int, propagating the conversion failure."""
        try:
            parsed_int = int(str(json_value))
        except c.EXC_TYPE_VALIDATION as exc:
            return r[int].fail(str(exc), exception=exc)
        return r[int].ok(parsed_int)

    @staticmethod
    def _to_optional_str(value: t.JsonValue | None) -> str | None:
        json_value: t.JsonPayload | None = value
        if json_value is None:
            return None
        if isinstance(json_value, Mapping) or (
            isinstance(json_value, Sequence) and not isinstance(json_value, str | bytes)
        ):
            return None
        if isinstance(json_value, str):
            return json_value
        return str(json_value)

    @staticmethod
    def _to_required_value(
        value: t.JsonValue | None,
        default: str = "",
    ) -> str:
        json_value: t.JsonPayload | None = value
        if json_value is None:
            return default
        if isinstance(json_value, Mapping) or (
            isinstance(json_value, Sequence) and not isinstance(json_value, str | bytes)
        ):
            return default
        if isinstance(json_value, str):
            return json_value
        return str(json_value)

    @staticmethod
    def _to_string_list(
        value: t.JsonValue | None,
    ) -> t.MutableSequenceOf[str] | None:
        json_value: t.JsonPayload | None = value
        if isinstance(json_value, Sequence) and not isinstance(json_value, str | bytes):
            list_value: t.MutableSequenceOf[str] = [str(item) for item in json_value]
            return list_value
        return None

    @override
    def can_handle_attribute(
        self,
        attr_definition: str | m.Ldif.SchemaAttribute,
    ) -> bool:
        """Check if RFC server can handle attribute definitions (abstract impl)."""
        _ = (self, attr_definition)
        return True

    @override
    def can_handle_objectclass(
        self,
        oc_definition: str | m.Ldif.SchemaObjectClass,
    ) -> bool:
        """Check if RFC server can handle objectClass definitions (abstract impl)."""
        _ = (self, oc_definition)
        return True

    def _detect_oc_via_constants(
        self,
        oc_definition: str | m.Ldif.SchemaObjectClass,
        *,
        settings: m.Ldif.ServerPatternsConfig,
        name_regex: str,
    ) -> bool:
        """Detect objectClass definitions through centralized server pattern settings."""
        if isinstance(oc_definition, m.Ldif.SchemaObjectClass):
            matches_server_patterns: bool = u.Ldif.matches_server_patterns(
                value=oc_definition,
                settings=settings,
            )
            return matches_server_patterns
        if settings.oid_pattern and c.Ldif.compile_pattern(settings.oid_pattern).search(
            oc_definition,
        ):
            return True
        name_matches = c.Ldif.compile_pattern(name_regex, ignorecase=True).findall(
            oc_definition,
        )
        attr_names = {name.lower() for name in settings.attr_names}
        return any(name.lower() in attr_names for name in name_matches)

    def create_metadata(
        self,
        original_format: str,
        extensions: m.Ldif.DynamicMetadata | None = None,
    ) -> m.Ldif.ServerMetadata:
        """Create server metadata with consistent server-specific extensions."""
        server_type_value = self._get_server_type()
        all_extensions = m.Ldif.DynamicMetadata()
        all_extensions[c.Ldif.ACL_ORIGINAL_FORMAT] = original_format
        if extensions:
            all_extensions.update(extensions.to_dict())
        return m.Ldif.ServerMetadata(
            server_type=server_type_value,
            extensions=all_extensions,
        )

    def extract_schemas_from_ldif(
        self,
        ldif_content: str,
        *,
        validate_dependencies: bool = False,
    ) -> p.Result[
        MutableMapping[
            str,
            t.MutableSequenceOf[m.Ldif.SchemaAttribute]
            | t.MutableSequenceOf[m.Ldif.SchemaObjectClass],
        ]
    ]:
        """Extract schema definitions from LDIF using u."""
        try:
            return self._extract_schemas_from_ldif(
                ldif_content,
                validate_dependencies=validate_dependencies,
            )
        except c.Ldif.EXC_LDIF_PARSE as e:
            FlextLdifServersRfcSchema._module_logger.exception(
                "Schema extraction failed",
            )
            return r[
                MutableMapping[
                    str,
                    t.MutableSequenceOf[m.Ldif.SchemaAttribute]
                    | t.MutableSequenceOf[m.Ldif.SchemaObjectClass],
                ]
            ].fail_op("Schema extraction", e)

    def _extract_schemas_from_ldif(
        self,
        ldif_content: str,
        *,
        validate_dependencies: bool,
    ) -> p.Result[
        MutableMapping[
            str,
            t.MutableSequenceOf[m.Ldif.SchemaAttribute]
            | t.MutableSequenceOf[m.Ldif.SchemaObjectClass],
        ]
    ]:
        """Extract schema definitions and optionally validate dependencies."""
        attributes_parsed = u.Ldif.extract_attributes_from_lines(
            ldif_content,
            self.parse_attribute,
        )
        if validate_dependencies:
            available_attrs = u.Ldif.build_available_attributes_set(
                attributes_parsed,
            )
            validation_result = self._hook_validate_attributes(
                attributes_parsed,
                available_attrs,
            )
            if not validation_result.success:
                return r[
                    MutableMapping[
                        str,
                        t.MutableSequenceOf[m.Ldif.SchemaAttribute]
                        | t.MutableSequenceOf[m.Ldif.SchemaObjectClass],
                    ]
                ].fail_op("Attribute validation", validation_result.error)

        objectclasses_parsed = u.Ldif.extract_objectclasses_from_lines(
            ldif_content,
            self.parse_objectclass,
        )
        schema_dict: MutableMapping[
            str,
            t.MutableSequenceOf[m.Ldif.SchemaAttribute]
            | t.MutableSequenceOf[m.Ldif.SchemaObjectClass],
        ] = {
            str(c.Ldif.DictKeys.ATTRIBUTES): attributes_parsed,
            str(c.Ldif.DictKeys.OBJECTCLASS): objectclasses_parsed,
        }
        return r[
            MutableMapping[
                str,
                t.MutableSequenceOf[m.Ldif.SchemaAttribute]
                | t.MutableSequenceOf[m.Ldif.SchemaObjectClass],
            ]
        ].ok(schema_dict)

    def should_filter_out_attribute(self, _attribute: m.Ldif.SchemaAttribute) -> bool:
        """RFC server does not filter attributes."""
        _ = self
        return False

    def should_filter_out_objectclass(
        self,
        _objectclass: m.Ldif.SchemaObjectClass,
    ) -> bool:
        """RFC server does not filter objectClasses."""
        _ = (self, _objectclass)
        return False

    def _build_attribute_parts(
        self,
        attr_data: m.Ldif.SchemaAttribute,
    ) -> t.MutableSequenceOf[str]:
        """Build RFC attribute definition parts."""
        parts: t.MutableSequenceOf[str] = u.Ldif.build_attribute_parts_with_metadata(
            attr_data,
            restore_original=u.Ldif.should_restore_schema_original_format(
                attr_data.metadata,
                self._get_server_type(),
            ),
        )
        return parts

    def _build_objectclass_metadata(
        self,
        oc_definition: str,
        metadata_extensions: MutableMapping[
            str,
            t.MutableSequenceOf[str] | str | bool | None,
        ],
    ) -> m.Ldif.ServerMetadata:
        """Build objectClass metadata with extensions."""
        server_type = self._get_server_type()
        metadata_extensions[c.Ldif.SCHEMA_SOURCE_SERVER] = server_type
        metadata = m.Ldif.ServerMetadata(
            server_type=server_type,
            extensions=m.Ldif.DynamicMetadata.model_validate(metadata_extensions)
            if metadata_extensions
            else m.Ldif.DynamicMetadata(),
            original_server_type=server_type,
            target_server_type=server_type,
        )
        u.Ldif.preserve_schema_formatting(metadata, oc_definition)
        return metadata

    def _build_objectclass_parts(
        self,
        oc_data: m.Ldif.SchemaObjectClass,
    ) -> t.MutableSequenceOf[str]:
        """Build RFC objectClass definition parts."""
        parts: t.MutableSequenceOf[str] = u.Ldif.build_objectclass_parts_with_metadata(
            oc_data,
            restore_original=u.Ldif.should_restore_schema_original_format(
                oc_data.metadata,
                self._get_server_type(),
            ),
        )
        return parts

    def _ensure_x_origin(
        self,
        output_str: str,
        metadata: m.Ldif.ServerMetadata | None,
    ) -> str:
        """Ensure X-ORIGIN extension is present if in metadata."""
        result = output_str
        if metadata is not None:
            extensions = metadata.extensions
            if extensions:
                x_origin_raw: t.JsonPayload | None = extensions.get(c.Ldif.X_ORIGIN)
                if (
                    isinstance(x_origin_raw, str)
                    and "X-ORIGIN" not in output_str
                    and output_str.endswith(")")
                ):
                    x_origin_str = f" X-ORIGIN '{x_origin_raw}'"
                    result = output_str.rstrip(")") + x_origin_str + ")"
        return result

    @override
    def _parse_attribute(
        self,
        attr_definition: str,
    ) -> p.Result[m.Ldif.SchemaAttribute]:
        """Parse RFC 4512 attribute definition using generalized parser."""
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
            return r[m.Ldif.SchemaAttribute].fail(
                parse_result_raw.error or "Attribute parsing failed",
            )
        parsed_raw = parse_result_raw.value
        parsed: t.Ldif.MutableMetadataMapping = dict(parsed_raw)
        syntax = parsed.get("syntax")
        syntax_str = str(syntax) if syntax is not None else None
        syntax_validation_error = self._extract_syntax_validation_error(
            parsed.get("syntax_validation"),
        )
        attribute_oid = str(parsed.get("oid")) if parsed.get("oid") else None
        metadata = FlextLdifServersBaseSchema.build_attribute_metadata(
            attr_definition,
            syntax_str,
            syntax_validation_error,
            attribute_oid=attribute_oid,
            equality_oid=str(parsed.get("equality"))
            if parsed.get("equality")
            else None,
            ordering_oid=str(parsed.get("ordering"))
            if parsed.get("ordering")
            else None,
            substr_oid=str(parsed.get("substr")) if parsed.get("substr") else None,
            sup_oid=str(parsed.get("sup")) if parsed.get("sup") else None,
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
        """Parse RFC 4512 objectClass definition using core parser."""
        parse_result = self._parse_objectclass_core(oc_definition)
        if parse_result.failure:
            return parse_result
        return self._hook_post_parse_objectclass(parse_result.value)

    def _parse_objectclass_core(
        self,
        oc_definition: str,
    ) -> p.Result[m.Ldif.SchemaObjectClass]:
        """Core RFC 4512 objectClass parsing per Section 4.1.1."""
        try:
            return self._parse_rfc_objectclass_core(oc_definition)
        except c.EXC_BASIC_TYPE as e:
            FlextLdifServersRfcSchema._module_logger.exception(
                "RFC objectClass parsing exception",
            )
            return r[m.Ldif.SchemaObjectClass].fail_op("RFC objectClass parsing", e)

    def _parse_rfc_objectclass_core(
        self,
        oc_definition: str,
    ) -> p.Result[m.Ldif.SchemaObjectClass]:
        """Parse RFC objectClass definition into the canonical model."""
        parsed = u.Ldif.parse_objectclass(oc_definition)
        metadata_extensions = self._convert_extensions_for_server(
            self._coerce_dynamic_metadata(parsed.get("metadata_extensions")),
        )
        metadata_extensions[c.Ldif.ORIGINAL_FORMAT] = oc_definition.strip()
        metadata_extensions[c.Ldif.SCHEMA_ORIGINAL_STRING_COMPLETE] = oc_definition
        objectclass_oid = parsed.get("oid")
        match objectclass_oid:
            case None:
                FlextLdifServersBaseSchema.validate_and_track_oid(
                    metadata_extensions,
                    objectclass_oid,
                    "objectClass",
                )
            case str() as objectclass_oid_str:
                FlextLdifServersBaseSchema.validate_and_track_oid(
                    metadata_extensions,
                    objectclass_oid_str,
                    "objectClass",
                )
            case _:
                pass
        objectclass_sup_oid = parsed.get("sup")
        match objectclass_sup_oid:
            case None:
                FlextLdifServersBaseSchema.validate_and_track_oid(
                    metadata_extensions,
                    objectclass_sup_oid,
                    "objectClass SUP",
                )
            case str() as objectclass_sup_oid_str:
                FlextLdifServersBaseSchema.validate_and_track_oid(
                    metadata_extensions,
                    objectclass_sup_oid_str,
                    "objectClass SUP",
                )
            case _:
                pass
        must_list = self._to_string_list(parsed.get("must"))
        self._validate_oid_list(must_list, "MUST", metadata_extensions)
        may_list = self._to_string_list(parsed.get("may"))
        self._validate_oid_list(may_list, "MAY", metadata_extensions)
        metadata = self._build_objectclass_metadata(
            oc_definition,
            metadata_extensions,
        )
        objectclass = m.Ldif.SchemaObjectClass.model_validate({
            "oid": self._to_required_value(parsed.get("oid")),
            "name": self._to_required_value(parsed.get("name")),
            "desc": self._to_optional_str(parsed.get("desc")),
            "sup": self._to_optional_str_or_list(parsed.get("sup")),
            "kind": self._to_required_value(parsed.get("kind"), default="STRUCTURAL"),
            "must": self._to_string_list(parsed.get("must")),
            "may": self._to_string_list(parsed.get("may")),
            "metadata": metadata,
        })
        return r[m.Ldif.SchemaObjectClass].ok(objectclass)

    def _post_write_attribute(self, written_str: str) -> str:
        """Hook for subclasses to transform written attribute string."""
        return written_str

    def _post_write_objectclass(self, written_str: str) -> str:
        """Hook for subclasses to transform written objectClass string."""
        return written_str

    def _transform_attribute_for_write(
        self,
        attr_data: m.Ldif.SchemaAttribute,
    ) -> m.Ldif.SchemaAttribute:
        """Hook for subclasses to transform attribute before writing."""
        return attr_data

    def _transform_objectclass_for_write(
        self,
        oc_data: m.Ldif.SchemaObjectClass,
    ) -> m.Ldif.SchemaObjectClass:
        """Hook for subclasses to transform objectClass before writing."""
        return oc_data

    def _validate_oid_list(
        self,
        oids: t.MutableSequenceOf[str] | None,
        oid_type: str,
        metadata_extensions: MutableMapping[
            str,
            t.MutableSequenceOf[str] | str | bool | None,
        ],
    ) -> None:
        """Validate OID list and track in metadata."""
        if not oids:
            return
        for idx, oid in enumerate(oids):
            match oid:
                case str() as oid_str if oid_str:
                    FlextLdifServersBaseSchema.validate_and_track_oid(
                        metadata_extensions,
                        oid_str,
                        f"objectClass {oid_type}[{idx}]",
                    )
                case _:
                    pass

    @override
    def _write_attribute(self, attr_data: m.Ldif.SchemaAttribute) -> p.Result[str]:
        """Write attribute to RFC-compliant string format (internal)."""
        return self._write_schema_item(attr_data)

    @override
    def _write_objectclass(self, oc_data: m.Ldif.SchemaObjectClass) -> p.Result[str]:
        """Write objectClass to RFC-compliant string format (internal)."""
        return self._write_schema_item(oc_data)

    def _write_schema_item(
        self,
        data: m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass,
    ) -> p.Result[str]:
        """Write schema item (attribute or objectClass) to RFC-compliant format."""
        try:
            return self._write_schema_item_core(data)
        except c.EXC_BASIC_TYPE as e:
            item_type = (
                "attribute"
                if isinstance(data, m.Ldif.SchemaAttribute)
                else "objectclass"
            )
            FlextLdifServersRfcSchema._module_logger.exception(
                "RFC %s writing exception",
                item_type,
            )
            return r[str].fail(f"RFC {item_type} writing failed: {e}")

    def _write_schema_item_core(
        self,
        data: m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass,
    ) -> p.Result[str]:
        """Write schema item after server-specific transforms."""
        if isinstance(data, m.Ldif.SchemaAttribute):
            attr_transformed = self._transform_attribute_for_write(data)
            if not attr_transformed.oid:
                return r[str].fail("RFC attribute writing failed: missing OID")
            parts = self._build_attribute_parts(attr_transformed)
            written_str = " ".join(parts)
            transformed_str = self._post_write_attribute(written_str)
            if attr_transformed.metadata:
                fmt = attr_transformed.metadata.schema_format_details
                if fmt:
                    attr_case = getattr(
                        fmt,
                        "attribute_case",
                        c.Ldif.ATTRIBUTE_TYPES,
                    )
                    attr_types_lower = c.Ldif.ATTRIBUTE_TYPES.lower()
                    if attr_types_lower in transformed_str.lower():
                        transformed_str = c.Ldif.sub_pattern(
                            f"{attr_types_lower}:",
                            f"{attr_case}:",
                            transformed_str,
                            ignorecase=True,
                        )
            return r[str].ok(
                self._ensure_x_origin(transformed_str, attr_transformed.metadata),
            )
        oc_transformed = self._transform_objectclass_for_write(data)
        if not oc_transformed.oid:
            return r[str].fail("RFC objectclass writing failed: missing OID")
        parts = self._build_objectclass_parts(oc_transformed)
        written_str = " ".join(parts)
        transformed_str = self._post_write_objectclass(written_str)
        return r[str].ok(
            self._ensure_x_origin(transformed_str, oc_transformed.metadata),
        )
