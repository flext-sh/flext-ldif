"""RFC 4512 Compliant Server Quirks - Base LDAP Schema/ACL/Entry Implementation."""

from __future__ import annotations

import re
import struct
from collections.abc import Mapping, MutableMapping, MutableSequence, Sequence
from datetime import datetime
from typing import Self, overload, override

from flext_core import FlextLogger, r
from flext_ldif import FlextLdifServersBase, FlextLdifServersBaseSchema, c, m, p, t, u

logger = FlextLogger(__name__)


class FlextLdifServersRfcSchema(FlextLdifServersBase.Schema):
    """RFC 4512 Compliant Schema Quirk - STRICT Implementation."""

    def __new__(
        cls,
        schema_service: p.Ldif.SchemaQuirk | None = None,
        parent_quirk: p.Ldif.SchemaQuirk | None = None,
        **kwargs: t.Scalar | m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass,
    ) -> Self:
        """Override __new__ to support auto-execute and processor instantiation."""
        instance = object.__new__(cls)
        filtered_kwargs = {
            "attr_definition",
            "oc_definition",
            "attr_model",
            "oc_model",
            "operation",
            "_parent_quirk",
            "parent_quirk",
        }
        _ = {k: v for k, v in kwargs.items() if k not in filtered_kwargs}
        parent_quirk_raw = (
            parent_quirk if parent_quirk is not None else kwargs.get("_parent_quirk")
        )
        parent_quirk_value: p.Ldif.SchemaQuirk | None = (
            parent_quirk_raw
            if isinstance(parent_quirk_raw, p.Ldif.SchemaQuirk)
            else None
        )
        schema_instance: Self = instance
        super(FlextLdifServersBase.Schema, schema_instance).__init__()
        if schema_service is not None:
            object.__setattr__(schema_instance, "_schema_service", schema_service)
        if parent_quirk_value is not None:
            object.__setattr__(schema_instance, "_parent_quirk", parent_quirk_value)
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
            data: str | m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass | None = None
            if attr_def is not None:
                data = attr_def
            elif oc_def is not None:
                data = oc_def
            elif attr_mod is not None:
                data = attr_mod
            elif oc_mod is not None:
                data = oc_mod
            result = schema_instance.execute(data=data, operation=op)
            unwrapped = result.value
            if isinstance(unwrapped, cls):
                return unwrapped
            return instance
        return instance

    def __init__(
        self,
        schema_service: p.Ldif.SchemaQuirk | None = None,
        parent_quirk: p.Ldif.SchemaQuirk | None = None,
        **kwargs: t.Scalar | m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass,
    ) -> None:
        """Initialize RFC schema quirk service."""
        filtered_kwargs: t.MutableConfigurationMapping = {}
        excluded_keys = {
            "_parent_quirk",
            "parent_quirk",
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
            if u.is_scalar(value):
                filtered_kwargs[key] = value
        schema_service_typed: p.Ldif.SchemaQuirk | None = schema_service
        FlextLdifServersBaseSchema.__init__(
            self,
            _schema_service=schema_service_typed,
            _parent_quirk=None,
            **filtered_kwargs,
        )
        if parent_quirk is not None:
            object.__setattr__(self, "_parent_quirk", parent_quirk)

    @overload
    def __call__(
        self,
        attr_definition: str,
        *,
        oc_definition: None = None,
        attr_model: None = None,
        oc_model: None = None,
        operation: str | None = None,
    ) -> str | m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass: ...

    @overload
    def __call__(
        self,
        *,
        attr_definition: None = None,
        oc_definition: str,
        attr_model: None = None,
        oc_model: None = None,
        operation: str | None = None,
    ) -> str | m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass: ...

    @overload
    def __call__(
        self,
        *,
        attr_definition: None = None,
        oc_definition: None = None,
        attr_model: m.Ldif.SchemaAttribute,
        oc_model: None = None,
        operation: str | None = None,
    ) -> str: ...

    @overload
    def __call__(
        self,
        *,
        attr_definition: None = None,
        oc_definition: None = None,
        attr_model: None = None,
        oc_model: m.Ldif.SchemaObjectClass,
        operation: str | None = None,
    ) -> str: ...

    @overload
    def __call__(
        self,
        attr_definition: str | None = None,
        oc_definition: str | None = None,
        attr_model: m.Ldif.SchemaAttribute | None = None,
        oc_model: m.Ldif.SchemaObjectClass | None = None,
        operation: str | None = None,
    ) -> str | m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass: ...

    def __call__(
        self,
        attr_definition: str | None = None,
        oc_definition: str | None = None,
        attr_model: m.Ldif.SchemaAttribute | None = None,
        oc_model: m.Ldif.SchemaObjectClass | None = None,
        operation: str | None = None,
    ) -> str | m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass:
        """Callable interface - automatic polymorphic processor."""
        data: str | m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass | None = None
        if attr_definition is not None:
            data = attr_definition
        elif oc_definition is not None:
            data = oc_definition
        elif attr_model is not None:
            data = attr_model
        elif oc_model is not None:
            data = oc_model
        result = self.execute(data=data, operation=operation)
        return result.value

    @classmethod
    def _extract_syntax_validation_error(
        cls,
        value: t.NormalizedValue | None,
    ) -> str | None:
        syntax_validation = cls._coerce_dynamic_metadata(value)
        syntax_error = syntax_validation.get("syntax_validation_error")
        if isinstance(syntax_error, str):
            return syntax_error
        return None

    @classmethod
    def _to_optional_str_or_list(
        cls,
        value: t.NormalizedValue | None,
    ) -> str | MutableSequence[str] | None:
        if isinstance(value, str):
            return value
        return cls._to_string_list(value)

    @staticmethod
    def _build_attribute_metadata(
        attr_definition: str,
        syntax: str | None,
        syntax_validation_error: str | None,
        attribute_oid: str | None = None,
        equality_oid: str | None = None,
        ordering_oid: str | None = None,
        substr_oid: str | None = None,
        sup_oid: str | None = None,
        _server_type: str | None = None,
    ) -> m.Ldif.QuirkMetadata | None:
        """Build metadata for attribute including extensions and OID validation."""
        server_type_to_use = _server_type or "rfc"
        return FlextLdifServersBase.Schema.build_attribute_metadata(
            attr_definition,
            syntax,
            syntax_validation_error,
            attribute_oid=attribute_oid,
            equality_oid=equality_oid,
            ordering_oid=ordering_oid,
            substr_oid=substr_oid,
            sup_oid=sup_oid,
            server_type=server_type_to_use,
        )

    @staticmethod
    def _coerce_dynamic_metadata(
        value: t.NormalizedValue | None,
    ) -> m.Ldif.DynamicMetadata:
        if isinstance(value, m.Ldif.DynamicMetadata):
            return value
        if isinstance(value, Mapping):
            return m.Ldif.DynamicMetadata.model_validate(value)
        return m.Ldif.DynamicMetadata()

    @staticmethod
    def _convert_extensions_for_quirk(
        metadata: m.Ldif.DynamicMetadata,
    ) -> t.Ldif.SchemaExtensionsMapping:
        extensions: t.Ldif.SchemaExtensionsMapping = {}
        for key, value in metadata.items():
            if isinstance(value, bool):
                extensions[key] = value
                continue
            if isinstance(value, str):
                extensions[key] = value
                continue
            if isinstance(value, list):
                extensions[key] = [str(item) for item in value]
                continue
            if isinstance(value, datetime):
                extensions[key] = value.isoformat()
                continue
            if isinstance(value, (int, float)):
                extensions[key] = str(value)
                continue
            extensions[key] = str(value)
        return extensions

    @staticmethod
    def _to_optional_int(value: t.NormalizedValue) -> int | None:
        match value:
            case int() as int_value:
                return int_value
            case str() as str_value if str_value:
                return int(str_value)
            case _:
                return None

    @staticmethod
    def _to_optional_str(value: t.NormalizedValue) -> str | None:
        match value:
            case str() as str_value:
                return str_value
            case _ if value and value is not True:
                return str(value)
            case _:
                return None

    @staticmethod
    def _to_required_str(value: t.NormalizedValue, default: str = "") -> str:
        match value:
            case str() as str_value:
                return str_value
            case _ if value:
                return str(value)
            case _:
                return default

    @staticmethod
    def _to_string_list(value: t.NormalizedValue | None) -> MutableSequence[str] | None:
        if isinstance(value, Sequence) and (
            not isinstance(value, str | bytes | bytearray)
        ):
            return [str(item) for item in value]
        return None

    @override
    def can_handle_attribute(
        self,
        attr_definition: str | m.Ldif.SchemaAttribute,
    ) -> bool:
        """Check if RFC quirk can handle attribute definitions (abstract impl)."""
        _ = (self, attr_definition)
        return True

    @override
    def can_handle_objectclass(
        self,
        oc_definition: str | m.Ldif.SchemaObjectClass,
    ) -> bool:
        """Check if RFC quirk can handle objectClass definitions (abstract impl)."""
        _ = (self, oc_definition)
        return True

    def create_metadata(
        self,
        original_format: str,
        extensions: m.Ldif.DynamicMetadata | None = None,
    ) -> m.Ldif.QuirkMetadata:
        """Create quirk metadata with consistent server-specific extensions."""
        server_type_value = self._get_server_type()
        all_extensions = m.Ldif.DynamicMetadata()
        all_extensions[c.Ldif.ACL_ORIGINAL_FORMAT] = original_format
        if extensions:
            all_extensions.update(extensions.to_dict())
        return m.Ldif.QuirkMetadata(
            quirk_type=server_type_value,
            extensions=all_extensions,
        )

    def extract_schemas_from_ldif(
        self,
        ldif_content: str,
        *,
        validate_dependencies: bool = False,
    ) -> r[
        MutableMapping[
            str,
            MutableSequence[m.Ldif.SchemaAttribute]
            | MutableSequence[m.Ldif.SchemaObjectClass],
        ]
    ]:
        """Extract schema definitions from LDIF using u."""
        try:

            def parse_attribute_domain(
                attr_definition: str,
            ) -> r[m.Ldif.SchemaAttribute]:
                return self.parse_attribute(attr_definition).map(
                    lambda attr: m.Ldif.SchemaAttribute.model_validate(
                        attr.model_dump(),
                    ),
                )

            attributes_parsed = u.Ldif.extract_attributes_from_lines(
                ldif_content,
                parse_attribute_domain,
            )
            attributes_parsed_model: MutableSequence[m.Ldif.SchemaAttribute] = [
                m.Ldif.SchemaAttribute.model_validate(attr.model_dump())
                for attr in attributes_parsed
            ]
            if validate_dependencies:
                available_attrs = u.Ldif.build_available_attributes_set(
                    attributes_parsed,
                )
                validation_result = self._hook_validate_attributes(
                    attributes_parsed_model,
                    available_attrs,
                )
                if not validation_result.success:
                    return r[
                        MutableMapping[
                            str,
                            MutableSequence[m.Ldif.SchemaAttribute]
                            | MutableSequence[m.Ldif.SchemaObjectClass],
                        ]
                    ].fail(f"Attribute validation failed: {validation_result.error}")

            def parse_objectclass_domain(
                oc_definition: str,
            ) -> r[m.Ldif.SchemaObjectClass]:
                return self.parse_objectclass(oc_definition).map(
                    lambda oc: m.Ldif.SchemaObjectClass.model_validate(oc.model_dump()),
                )

            objectclasses_parsed = u.Ldif.extract_objectclasses_from_lines(
                ldif_content,
                parse_objectclass_domain,
            )
            objectclasses_parsed_model: MutableSequence[m.Ldif.SchemaObjectClass] = [
                m.Ldif.SchemaObjectClass.model_validate(oc.model_dump())
                for oc in objectclasses_parsed
            ]
            schema_dict: MutableMapping[
                str,
                MutableSequence[m.Ldif.SchemaAttribute]
                | MutableSequence[m.Ldif.SchemaObjectClass],
            ] = {
                str(c.Ldif.DictKeys.ATTRIBUTES): attributes_parsed_model,
                str(c.Ldif.DictKeys.OBJECTCLASS): objectclasses_parsed_model,
            }
            return r[
                MutableMapping[
                    str,
                    MutableSequence[m.Ldif.SchemaAttribute]
                    | MutableSequence[m.Ldif.SchemaObjectClass],
                ]
            ].ok(schema_dict)
        except (
            ValueError,
            KeyError,
            AttributeError,
            UnicodeDecodeError,
            struct.error,
        ) as e:
            logger.exception("Schema extraction failed")
            return r[
                MutableMapping[
                    str,
                    MutableSequence[m.Ldif.SchemaAttribute]
                    | MutableSequence[m.Ldif.SchemaObjectClass],
                ]
            ].fail(f"Schema extraction failed: {e}")

    def should_filter_out_attribute(self, _attribute: m.Ldif.SchemaAttribute) -> bool:
        """RFC quirk does not filter attributes."""
        _ = self
        return False

    def should_filter_out_objectclass(
        self,
        _objectclass: m.Ldif.SchemaObjectClass,
    ) -> bool:
        """RFC quirk does not filter objectClasses."""
        _ = (self, _objectclass)
        return False

    def _build_attribute_parts(
        self,
        attr_data: m.Ldif.SchemaAttribute,
    ) -> MutableSequence[str]:
        """Build RFC attribute definition parts."""
        return u.Ldif.build_attribute_parts_with_metadata(
            attr_data,
            restore_original=u.Ldif.should_restore_schema_original_format(
                attr_data.metadata,
                self._get_server_type(),
            ),
        )

    def _build_objectclass_metadata(
        self,
        oc_definition: str,
        metadata_extensions: MutableMapping[
            str,
            MutableSequence[str] | str | bool | None,
        ],
    ) -> m.Ldif.QuirkMetadata:
        """Build objectClass metadata with extensions."""
        server_type = self._get_server_type()
        metadata_extensions[c.Ldif.SCHEMA_SOURCE_SERVER] = server_type
        metadata = m.Ldif.QuirkMetadata(
            quirk_type=server_type,
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
    ) -> MutableSequence[str]:
        """Build RFC objectClass definition parts."""
        return u.Ldif.build_objectclass_parts_with_metadata(
            oc_data,
            restore_original=u.Ldif.should_restore_schema_original_format(
                oc_data.metadata,
                self._get_server_type(),
            ),
        )

    def _ensure_x_origin(
        self,
        output_str: str,
        metadata: m.Ldif.QuirkMetadata | None,
    ) -> str:
        """Ensure X-ORIGIN extension is present if in metadata."""
        if not metadata or not metadata.extensions:
            return output_str
        x_origin_raw = metadata.extensions.get(c.Ldif.X_ORIGIN)
        if not isinstance(x_origin_raw, str):
            return output_str
        if ")" not in output_str or "X-ORIGIN" in output_str:
            return output_str
        x_origin_str = f" X-ORIGIN '{x_origin_raw}'"
        return output_str.rstrip(")") + x_origin_str + ")"

    @override
    def _parse_attribute(self, attr_definition: str) -> r[m.Ldif.SchemaAttribute]:
        """Parse RFC 4512 attribute definition using generalized parser."""
        server_type = self._get_server_type()

        def parse_parts_hook(
            definition: str,
        ) -> r[t.MutableContainerMapping]:
            return u.Ldif.parse_attribute(definition)

        parse_result_raw = u.Ldif.parse(
            definition=attr_definition,
            server_type=server_type,
            parse_parts_hook=parse_parts_hook,
        )
        if parse_result_raw.failure:
            return r[m.Ldif.SchemaAttribute].fail(
                parse_result_raw.error or "Attribute parsing failed",
            )
        parsed = parse_result_raw.value
        syntax = parsed.get("syntax")
        syntax_str = str(syntax) if syntax is not None else None
        syntax_validation_error = self._extract_syntax_validation_error(
            parsed.get("syntax_validation"),
        )
        attribute_oid = str(parsed.get("oid")) if parsed.get("oid") else None
        metadata = self._build_attribute_metadata(
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
            _server_type=server_type,
        )
        attr_name = self._to_optional_str(parsed.get("name"))
        if attr_name is None:
            attr_name = self._to_required_str(parsed.get("oid"))
        attr_model = m.Ldif.SchemaAttribute(
            oid=self._to_required_str(parsed.get("oid")),
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
    def _parse_objectclass(self, oc_definition: str) -> r[m.Ldif.SchemaObjectClass]:
        """Parse RFC 4512 objectClass definition using core parser."""
        parse_result = self._parse_objectclass_core(oc_definition)
        if parse_result.failure:
            return parse_result
        return self._hook_post_parse_objectclass(parse_result.value)

    def _parse_objectclass_core(
        self,
        oc_definition: str,
    ) -> r[m.Ldif.SchemaObjectClass]:
        """Core RFC 4512 objectClass parsing per Section 4.1.1."""
        try:
            parsed = u.Ldif.parse_objectclass(oc_definition)
            metadata_extensions = self._convert_extensions_for_quirk(
                self._coerce_dynamic_metadata(parsed.get("metadata_extensions")),
            )
            metadata_extensions[c.Ldif.ORIGINAL_FORMAT] = oc_definition.strip()
            metadata_extensions[c.Ldif.SCHEMA_ORIGINAL_STRING_COMPLETE] = oc_definition
            objectclass_oid = parsed.get("oid")
            match objectclass_oid:
                case None:
                    FlextLdifServersBase.Schema.validate_and_track_oid(
                        metadata_extensions,
                        objectclass_oid,
                        "objectClass",
                    )
                case str() as objectclass_oid_str:
                    FlextLdifServersBase.Schema.validate_and_track_oid(
                        metadata_extensions,
                        objectclass_oid_str,
                        "objectClass",
                    )
                case _:
                    pass
            objectclass_sup_oid = parsed.get("sup")
            match objectclass_sup_oid:
                case None:
                    FlextLdifServersBase.Schema.validate_and_track_oid(
                        metadata_extensions,
                        objectclass_sup_oid,
                        "objectClass SUP",
                    )
                case str() as objectclass_sup_oid_str:
                    FlextLdifServersBase.Schema.validate_and_track_oid(
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
            oc_oid: str = self._to_required_str(parsed.get("oid"))
            oc_name: str = self._to_required_str(parsed.get("name"))
            oc_desc: str | None = self._to_optional_str(parsed.get("desc"))
            oc_sup = self._to_optional_str_or_list(parsed.get("sup"))
            oc_kind: str = self._to_required_str(
                parsed.get("kind"),
                default="STRUCTURAL",
            )
            oc_must = self._to_string_list(parsed.get("must"))
            oc_may = self._to_string_list(parsed.get("may"))
            objectclass = m.Ldif.SchemaObjectClass(
                oid=oc_oid,
                name=oc_name,
                desc=oc_desc,
                sup=oc_sup,
                kind=oc_kind,
                must=oc_must,
                may=oc_may,
                metadata=metadata,
            )
            return r[m.Ldif.SchemaObjectClass].ok(objectclass)
        except (ValueError, TypeError, AttributeError) as e:
            logger.exception("RFC objectClass parsing exception")
            return r[m.Ldif.SchemaObjectClass].fail(
                f"RFC objectClass parsing failed: {e}",
            )

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
        oids: MutableSequence[str] | None,
        oid_type: str,
        metadata_extensions: MutableMapping[
            str,
            MutableSequence[str] | str | bool | None,
        ],
    ) -> None:
        """Validate OID list and track in metadata."""
        if not oids:
            return
        for idx, oid in enumerate(oids):
            match oid:
                case str() as oid_str if oid_str:
                    FlextLdifServersBase.Schema.validate_and_track_oid(
                        metadata_extensions,
                        oid_str,
                        f"objectClass {oid_type}[{idx}]",
                    )
                case _:
                    pass

    @override
    def _write_attribute(self, attr_data: m.Ldif.SchemaAttribute) -> r[str]:
        """Write attribute to RFC-compliant string format (internal)."""
        return self._write_schema_item(attr_data)

    @override
    def _write_objectclass(self, oc_data: m.Ldif.SchemaObjectClass) -> r[str]:
        """Write objectClass to RFC-compliant string format (internal)."""
        return self._write_schema_item(oc_data)

    def _write_schema_item(
        self,
        data: m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass,
    ) -> r[str]:
        """Write schema item (attribute or objectClass) to RFC-compliant format."""
        try:
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
                            transformed_str = re.sub(
                                f"{attr_types_lower}:",
                                f"{attr_case}:",
                                transformed_str,
                                flags=re.IGNORECASE,
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
        except (ValueError, TypeError, AttributeError) as e:
            item_type = (
                "attribute"
                if isinstance(data, m.Ldif.SchemaAttribute)
                else "objectclass"
            )
            logger.exception("RFC %s writing exception", item_type)
            return r[str].fail(f"RFC {item_type} writing failed: {e}")
