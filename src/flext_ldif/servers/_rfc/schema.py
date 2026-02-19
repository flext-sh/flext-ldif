"""RFC 4512 Compliant Server Quirks - Base LDAP Schema/ACL/Entry Implementation."""

from __future__ import annotations

import re
from datetime import datetime
from typing import Literal, Self, overload

from flext_core import FlextLogger, FlextResult

from flext_ldif._models.domain import FlextLdifModelsDomains
from flext_ldif._utilities.attribute import FlextLdifUtilitiesAttribute
from flext_ldif._utilities.metadata import FlextLdifUtilitiesMetadata
from flext_ldif._utilities.schema import FlextLdifUtilitiesSchema
from flext_ldif.constants import c
from flext_ldif.models import m
from flext_ldif.servers._base.schema import FlextLdifServersBaseSchema
from flext_ldif.servers.base import FlextLdifServersBase
from flext_ldif.typings import FlextLdifTypes as t

logger = FlextLogger(__name__)


class FlextLdifServersRfcSchema(FlextLdifServersBase.Schema):
    """RFC 4512 Compliant Schema Quirk - STRICT Implementation."""

    def __init__(
        self,
        schema_service: object | None = None,
        parent_quirk: object | None = None,
        **kwargs: t.GeneralValueType,
    ) -> None:
        """Initialize RFC schema quirk service."""
        filtered_kwargs: dict[str, t.GeneralValueType] = {
            k: v
            for k, v in kwargs.items()
            if k not in {"_parent_quirk", "parent_quirk", "_schema_service"}
        }

        schema_service_typed: object = schema_service

        FlextLdifServersBaseSchema.__init__(
            self,
            _schema_service=schema_service_typed,
            _parent_quirk=None,
            **filtered_kwargs,
        )

        if parent_quirk is not None:
            object.__setattr__(self, "_parent_quirk", parent_quirk)

    def can_handle_attribute(
        self,
        attr_definition: str | m.Ldif.SchemaAttribute,
    ) -> bool:
        """Check if RFC quirk can handle attribute definitions (abstract impl)."""
        _ = (self, attr_definition)
        return True

    def can_handle_objectclass(
        self,
        oc_definition: str | m.Ldif.SchemaObjectClass,
    ) -> bool:
        """Check if RFC quirk can handle objectClass definitions (abstract impl)."""
        _ = (self, oc_definition)
        return True

    def should_filter_out_attribute(
        self,
        _attribute: m.Ldif.SchemaAttribute,
    ) -> bool:
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
    def _to_optional_str(value: object) -> str | None:
        if isinstance(value, str):
            return value
        if value and value is not True:
            return str(value)
        return None

    @staticmethod
    def _to_required_str(value: object, default: str = "") -> str:
        if isinstance(value, str):
            return value
        if value:
            return str(value)
        return default

    @staticmethod
    def _to_optional_int(value: object) -> int | None:
        if isinstance(value, int):
            return value
        if isinstance(value, str) and value:
            return int(value)
        return None

    def _parse_attribute(
        self,
        attr_definition: str,
    ) -> FlextResult[m.Ldif.SchemaAttribute]:
        """Parse RFC 4512 attribute definition using generalized parser."""
        server_type = self._get_server_type()

        def parse_parts_hook(
            definition: str,
        ) -> FlextResult[dict[str, t.GeneralValueType]]:
            return FlextLdifUtilitiesSchema.parse_attribute(definition)

        parse_result_raw = FlextLdifUtilitiesAttribute.parse(
            definition=attr_definition,
            server_type=server_type,
            parse_parts_hook=parse_parts_hook,
        )

        if parse_result_raw.is_failure:
            return FlextResult[m.Ldif.SchemaAttribute].fail(
                parse_result_raw.error or "Attribute parsing failed",
            )

        parsed = parse_result_raw.value

        metadata_extensions: dict[str, list[str] | str | bool | None] = {}
        extensions_raw = parsed.get("metadata_extensions")
        if isinstance(extensions_raw, dict):
            for key, value in extensions_raw.items():
                if not isinstance(key, str):
                    continue
                if isinstance(value, (str, bool)) or value is None:
                    metadata_extensions[key] = value
                    continue
                if isinstance(value, list) and all(
                    isinstance(item, str) for item in value
                ):
                    metadata_extensions[key] = [
                        item for item in value if isinstance(item, str)
                    ]

        syntax = parsed.get("syntax")
        syntax_str = str(syntax) if syntax is not None else None

        syntax_validation_error = None
        syntax_validation = parsed.get("syntax_validation")
        if isinstance(syntax_validation, dict):
            err = syntax_validation.get("syntax_validation_error")
            if isinstance(err, str):
                syntax_validation_error = err

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

    def _validate_oid_list(
        self,
        oids: list[str] | None,
        oid_type: str,
        metadata_extensions: dict[str, list[str] | str | bool | None],
    ) -> None:
        """Validate OID list and track in metadata."""
        if not oids or not isinstance(oids, (list, tuple)):
            return
        for idx, oid in enumerate(oids):
            if oid and isinstance(oid, str):
                FlextLdifServersBase.Schema.validate_and_track_oid(
                    metadata_extensions,
                    oid,
                    f"objectClass {oid_type}[{idx}]",
                )

    def _build_objectclass_metadata(
        self,
        oc_definition: str,
        metadata_extensions: dict[str, list[str] | str | bool | None],
    ) -> m.Ldif.QuirkMetadata:
        """Build objectClass metadata with extensions."""
        server_type: Literal["rfc"] = "rfc"
        metadata = m.Ldif.QuirkMetadata(
            quirk_type=server_type,
            extensions=m.Ldif.DynamicMetadata.model_validate(metadata_extensions)
            if metadata_extensions
            else m.Ldif.DynamicMetadata(),
        )
        FlextLdifUtilitiesMetadata.preserve_schema_formatting(
            metadata,
            oc_definition,
        )
        return metadata

    def _parse_objectclass(
        self,
        oc_definition: str,
    ) -> FlextResult[m.Ldif.SchemaObjectClass]:
        """Parse RFC 4512 objectClass definition using core parser."""
        parse_result = self._parse_objectclass_core(oc_definition)

        if parse_result.is_failure:
            return parse_result

        return self._hook_post_parse_objectclass(parse_result.value)

    def _parse_objectclass_core(
        self,
        oc_definition: str,
    ) -> FlextResult[m.Ldif.SchemaObjectClass]:
        """Core RFC 4512 objectClass parsing per Section 4.1.1."""
        try:
            parsed = FlextLdifUtilitiesSchema.parse_objectclass(oc_definition)

            metadata_extensions_raw = parsed["metadata_extensions"]

            if isinstance(metadata_extensions_raw, dict):
                metadata_extensions_raw_dict: dict[
                    str,
                    str | int | float | bool | datetime | list[str] | None,
                ] = {
                    k: ([str(vi) for vi in v] if isinstance(v, list) else v)
                    for k, v in metadata_extensions_raw.items()
                    if isinstance(k, str)
                    and (
                        isinstance(v, (str, int, float, bool, list))
                        or v is None
                        or isinstance(v, datetime)
                    )
                }
            else:
                metadata_extensions_raw_dict = {}

            metadata_extensions: dict[str, list[str] | str | bool | None] = {}
            for key, value in metadata_extensions_raw_dict.items():
                if isinstance(value, (str, bool, list)) or value is None:
                    metadata_extensions[key] = value
                elif isinstance(value, (int, float)):
                    metadata_extensions[key] = str(value)
                elif isinstance(value, datetime):
                    metadata_extensions[key] = value.isoformat()
                else:
                    metadata_extensions[key] = str(value)
            metadata_extensions[c.Ldif.MetadataKeys.ORIGINAL_FORMAT] = (
                oc_definition.strip()
            )
            metadata_extensions[c.Ldif.MetadataKeys.SCHEMA_ORIGINAL_STRING_COMPLETE] = (
                oc_definition
            )

            objectclass_oid = parsed.get("oid")
            if objectclass_oid is None or isinstance(objectclass_oid, str):
                FlextLdifServersBase.Schema.validate_and_track_oid(
                    metadata_extensions,
                    objectclass_oid,
                    "objectClass",
                )

            objectclass_sup_oid = parsed.get("sup")
            if objectclass_sup_oid is None or isinstance(objectclass_sup_oid, str):
                FlextLdifServersBase.Schema.validate_and_track_oid(
                    metadata_extensions,
                    objectclass_sup_oid,
                    "objectClass SUP",
                )

            must_val = parsed.get("must")
            must_list: list[str] | None = (
                [str(item) for item in must_val] if isinstance(must_val, list) else None
            )
            self._validate_oid_list(must_list, "MUST", metadata_extensions)

            may_val = parsed.get("may")
            may_list: list[str] | None = (
                [str(item) for item in may_val] if isinstance(may_val, list) else None
            )
            self._validate_oid_list(may_list, "MAY", metadata_extensions)

            metadata = self._build_objectclass_metadata(
                oc_definition,
                metadata_extensions,
            )

            oc_oid: str = self._to_required_str(parsed["oid"])
            oc_name: str = self._to_required_str(parsed["name"])
            oc_desc: str | None = self._to_optional_str(parsed["desc"])

            oc_sup_value = parsed["sup"]
            if isinstance(oc_sup_value, str):
                oc_sup: str | list[str] | None = oc_sup_value
            elif isinstance(oc_sup_value, list):
                oc_sup = [str(item) for item in oc_sup_value]
            else:
                oc_sup = None

            oc_kind: str = self._to_required_str(parsed["kind"], default="STRUCTURAL")

            oc_must_value = parsed["must"]
            oc_must: list[str] | None = (
                [str(item) for item in oc_must_value]
                if isinstance(oc_must_value, list)
                else None
            )

            oc_may_value = parsed["may"]
            oc_may: list[str] | None = (
                [str(item) for item in oc_may_value]
                if isinstance(oc_may_value, list)
                else None
            )

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

            return FlextResult[m.Ldif.SchemaObjectClass].ok(objectclass)

        except (ValueError, TypeError, AttributeError) as e:
            logger.exception("RFC objectClass parsing exception")
            return FlextResult[m.Ldif.SchemaObjectClass].fail(
                f"RFC objectClass parsing failed: {e}",
            )

    def _transform_objectclass_for_write(
        self,
        oc_data: m.Ldif.SchemaObjectClass,
    ) -> m.Ldif.SchemaObjectClass:
        """Hook for subclasses to transform objectClass before writing."""
        return oc_data

    def _post_write_objectclass(self, written_str: str) -> str:
        """Hook for subclasses to transform written objectClass string."""
        return written_str

    def _transform_attribute_for_write(
        self,
        attr_data: m.Ldif.SchemaAttribute,
    ) -> m.Ldif.SchemaAttribute:
        """Hook for subclasses to transform attribute before writing."""
        return attr_data

    def _post_write_attribute(self, written_str: str) -> str:
        """Hook for subclasses to transform written attribute string."""
        return written_str

    def _build_attribute_parts(
        self,
        attr_data: m.Ldif.SchemaAttribute,
    ) -> list[str]:
        """Build RFC attribute definition parts."""
        return FlextLdifUtilitiesSchema.build_attribute_parts_with_metadata(
            attr_data,
            restore_original=True,
        )

    def _build_objectclass_parts(
        self,
        oc_data: m.Ldif.SchemaObjectClass,
    ) -> list[str]:
        """Build RFC objectClass definition parts."""
        return FlextLdifUtilitiesSchema.build_objectclass_parts_with_metadata(
            oc_data,
            restore_original=True,
        )

    def _ensure_x_origin(
        self,
        output_str: str,
        metadata: FlextLdifModelsDomains.QuirkMetadata | None,
    ) -> str:
        """Ensure X-ORIGIN extension is present if in metadata."""
        if not metadata or not metadata.extensions:
            return output_str
        x_origin_raw = metadata.extensions.get(
            c.Ldif.MetadataKeys.X_ORIGIN,
        )
        if not isinstance(x_origin_raw, str):
            return output_str
        if ")" not in output_str or "X-ORIGIN" in output_str:
            return output_str
        x_origin_str = f" X-ORIGIN '{x_origin_raw}'"
        return output_str.rstrip(")") + x_origin_str + ")"

    def _write_schema_item(
        self,
        data: m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass,
    ) -> FlextResult[str]:
        """Write schema item (attribute or objectClass) to RFC-compliant format."""
        try:
            if isinstance(data, m.Ldif.SchemaAttribute):
                attr_transformed = self._transform_attribute_for_write(data)
                if not attr_transformed.oid:
                    return FlextResult[str].fail(
                        "RFC attribute writing failed: missing OID",
                    )
                parts = self._build_attribute_parts(attr_transformed)
                written_str = " ".join(parts)
                transformed_str = self._post_write_attribute(written_str)

                if attr_transformed.metadata:
                    fmt = attr_transformed.metadata.schema_format_details
                    if fmt:
                        attr_case = getattr(
                            fmt,
                            "attribute_case",
                            c.Ldif.SchemaFields.ATTRIBUTE_TYPES,
                        )
                        attr_types_lower = c.Ldif.SchemaFields.ATTRIBUTE_TYPES.lower()
                        if attr_types_lower in transformed_str.lower():
                            transformed_str = re.sub(
                                rf"{attr_types_lower}:",
                                f"{attr_case}:",
                                transformed_str,
                                flags=re.IGNORECASE,
                            )
                return FlextResult[str].ok(
                    self._ensure_x_origin(
                        transformed_str,
                        attr_transformed.metadata,
                    ),
                )

            oc_transformed = self._transform_objectclass_for_write(data)
            if not oc_transformed.oid:
                return FlextResult[str].fail(
                    "RFC objectclass writing failed: missing OID",
                )
            parts = self._build_objectclass_parts(oc_transformed)
            written_str = " ".join(parts)
            transformed_str = self._post_write_objectclass(written_str)

            return FlextResult[str].ok(
                self._ensure_x_origin(
                    transformed_str,
                    oc_transformed.metadata,
                ),
            )

        except (ValueError, TypeError, AttributeError) as e:
            item_type = (
                "attribute"
                if isinstance(data, m.Ldif.SchemaAttribute)
                else "objectclass"
            )
            logger.exception(f"RFC {item_type} writing exception")
            return FlextResult[str].fail(f"RFC {item_type} writing failed: {e}")

    def _write_attribute(
        self,
        attr_data: m.Ldif.SchemaAttribute,
    ) -> FlextResult[str]:
        """Write attribute to RFC-compliant string format (internal)."""
        if not isinstance(attr_data, m.Ldif.SchemaAttribute):
            return FlextResult[str].fail(
                f"Invalid attribute type: expected SchemaAttribute, "
                f"got {type(attr_data).__name__}",
            )
        return self._write_schema_item(attr_data)

    def _write_objectclass(
        self,
        oc_data: m.Ldif.SchemaObjectClass,
    ) -> FlextResult[str]:
        """Write objectClass to RFC-compliant string format (internal)."""
        if not isinstance(oc_data, m.Ldif.SchemaObjectClass):
            return FlextResult[str].fail(
                f"Invalid objectClass type: expected SchemaObjectClass, "
                f"got {type(oc_data).__name__}",
            )
        return self._write_schema_item(oc_data)

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

        if isinstance(
            result.value, (str, m.Ldif.SchemaAttribute, m.Ldif.SchemaObjectClass)
        ):
            return result.value
        msg = f"Unexpected return type: {type(result.value)}"
        raise TypeError(msg)

    def __new__(
        cls,
        schema_service: object | None = None,
        parent_quirk: object | None = None,
        **kwargs: t.GeneralValueType,
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

        parent_quirk_value: object | None = (
            parent_quirk_raw if parent_quirk_raw is not None else None
        )

        if not isinstance(instance, FlextLdifServersRfcSchema):
            error_msg = f"Invalid instance type: {type(instance)}"
            raise TypeError(error_msg)
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

    def create_metadata(
        self,
        original_format: str,
        extensions: m.Ldif.DynamicMetadata | None = None,
    ) -> m.Ldif.QuirkMetadata:
        """Create quirk metadata with consistent server-specific extensions."""
        server_type_value = self._get_server_type()

        all_extensions = m.Ldif.DynamicMetadata()
        all_extensions[c.Ldif.MetadataKeys.ACL_ORIGINAL_FORMAT] = original_format

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
    ) -> FlextResult[
        dict[
            str,
            list[m.Ldif.SchemaAttribute] | list[m.Ldif.SchemaObjectClass],
        ]
    ]:
        """Extract schema definitions from LDIF using u."""
        try:
            attributes_parsed = FlextLdifUtilitiesSchema.extract_attributes_from_lines(
                ldif_content,
                self.parse_attribute,
            )

            if validate_dependencies:
                available_attrs = (
                    FlextLdifUtilitiesSchema.build_available_attributes_set(
                        attributes_parsed,
                    )
                )

                validation_result = self._hook_validate_attributes(
                    attributes_parsed,
                    available_attrs,
                )
                if not validation_result.is_success:
                    return FlextResult[
                        dict[
                            str,
                            list[m.Ldif.SchemaAttribute]
                            | list[m.Ldif.SchemaObjectClass],
                        ]
                    ].fail(
                        f"Attribute validation failed: {validation_result.error}",
                    )

            objectclasses_parsed = (
                FlextLdifUtilitiesSchema.extract_objectclasses_from_lines(
                    ldif_content,
                    self.parse_objectclass,
                )
            )

            schema_dict: dict[
                str,
                list[m.Ldif.SchemaAttribute] | list[m.Ldif.SchemaObjectClass],
            ] = {
                c.Ldif.DictKeys.ATTRIBUTES: attributes_parsed,
                c.Ldif.DictKeys.OBJECTCLASS: objectclasses_parsed,
            }
            return FlextResult[
                dict[
                    str,
                    list[m.Ldif.SchemaAttribute] | list[m.Ldif.SchemaObjectClass],
                ]
            ].ok(schema_dict)

        except Exception as e:
            logger.exception(
                "Schema extraction failed",
            )
            return FlextResult[
                dict[
                    str,
                    list[m.Ldif.SchemaAttribute] | list[m.Ldif.SchemaObjectClass],
                ]
            ].fail(
                f"Schema extraction failed: {e}",
            )
