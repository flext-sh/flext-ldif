"""Oracle Unified Directory (OUD) Servers."""

from __future__ import annotations

from collections.abc import (
    MutableMapping,
)
from typing import override

from flext_ldif import FlextLdifServersRfc, c, m, p, r, t, u
from flext_ldif.servers._base.schema import FlextLdifServersBaseSchema
from flext_ldif.servers._oud.constants import FlextLdifServersOudConstants

logger = u.fetch_logger(__name__)


class FlextLdifServersOudSchema(FlextLdifServersRfc.Schema):
    """Oracle OUD Schema Implementation (RFC 4512 + OUD Extensions)."""

    def __init__(
        self,
        schema_service: p.Ldif.SchemaServer | None = None,
        parent_server: p.Ldif.SchemaServer | None = None,
        **kwargs: t.Ldif.Scalar | m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass,
    ) -> None:
        """Initialize OUD schema server."""
        filtered_kwargs: t.MutableConfigValueMapping = {
            k: v
            for k, v in kwargs.items()
            if k not in {"_parent_server", "_schema_service"}
            and isinstance(v, (str, float, bool))
        }
        FlextLdifServersBaseSchema.__init__(
            self,
            _schema_service=schema_service,
            _parent_server=None,
            **filtered_kwargs,
        )
        if parent_server is not None:
            object.__setattr__(self, "_parent_server", parent_server)

    @override
    def extract_schemas_from_ldif(
        self,
        ldif_content: str,
        *,
        validate_dependencies: bool = True,
    ) -> p.Result[
        MutableMapping[
            str,
            t.MutableSequenceOf[m.Ldif.SchemaAttribute]
            | t.MutableSequenceOf[m.Ldif.SchemaObjectClass],
        ]
    ]:
        """Extract and parse all schema definitions from LDIF content."""
        return super().extract_schemas_from_ldif(
            ldif_content,
            validate_dependencies=validate_dependencies,
        )

    def _transform_by_matching_rules(
        self,
        attr_data: m.Ldif.SchemaAttribute,
    ) -> tuple[str | None, str | None]:
        """Apply OUD-specific matching rule transformations."""
        fixed_equality = attr_data.equality
        fixed_substr = attr_data.substr
        if fixed_equality == "caseIgnoreSubstringsMatch":
            logger.warning(
                "Moved caseIgnoreSubstringsMatch from EQUALITY to SUBSTR",
                attribute_name=attr_data.name,
            )
            fixed_substr = "caseIgnoreSubstringsMatch"
            fixed_equality = None
        original_substr = fixed_substr
        fixed_substr = u.Ldif.replace_invalid_substr_rule(
            fixed_substr,
            FlextLdifServersOudConstants.INVALID_SUBSTR_RULES,
        )
        if fixed_substr != original_substr:
            logger.warning(
                "Replaced invalid SUBSTR rule",
                attribute_name=attr_data.name,
                attribute_oid=attr_data.oid,
                original_substr=original_substr or "",
                replacement_substr=fixed_substr or "",
            )
        return (fixed_equality, fixed_substr)

    def _apply_attribute_oid_metadata(
        self,
        attr: m.Ldif.SchemaAttribute,
    ) -> m.Ldif.SchemaAttribute:
        """Apply OID validation and tracking metadata to attribute."""
        if not attr or not attr.oid:
            return attr
        oid_str = attr.oid
        oid_validation = self._validate_attribute_oid(oid_str)
        if oid_validation.failure:
            return attr
        is_valid_oud_oid = oid_validation.value
        existing_metadata = attr.metadata
        if not existing_metadata:
            existing_metadata = m.Ldif.ServerMetadata.create_for("oud")
        current_extensions = (
            dict(existing_metadata.extensions) if existing_metadata.extensions else {}
        )
        current_extensions[c.Ldif.SYNTAX_OID_VALID] = is_valid_oud_oid
        if oid_str.endswith("-oid"):
            current_extensions["oid_format_extension"] = True
        return attr.model_copy(
            update={
                "metadata": existing_metadata.model_copy(
                    update={"extensions": current_extensions},
                ),
            },
        )

    def _collect_attribute_extensions(
        self,
        attr: m.Ldif.SchemaAttribute,
    ) -> t.MutableSequenceOf[str]:
        """Collect OUD X-* extensions from attribute."""
        extensions: t.MutableSequenceOf[str] = []
        if attr.x_origin:
            extensions.append("X-ORIGIN")
        if attr.x_file_ref:
            extensions.append("X-FILE-REF")
        if attr.x_name:
            extensions.append("X-NAME")
        if attr.x_alias:
            extensions.append("X-ALIAS")
        if attr.x_oid:
            extensions.append("X-OID")
        return extensions

    @override
    def _hook_post_parse_attribute(
        self,
        attr: m.Ldif.SchemaAttribute,
    ) -> p.Result[m.Ldif.SchemaAttribute]:
        """Hook: Validate OUD-specific attribute features after RFC parsing."""
        if not attr or not attr.oid:
            return r[m.Ldif.SchemaAttribute].ok(attr)
        normalized_equality, normalized_substr = u.Ldif.normalize_matching_rules(
            attr.equality,
            attr.substr,
            replacements=FlextLdifServersOudConstants.MATCHING_RULE_TO_RFC,
            normalized_substr_values=FlextLdifServersOudConstants.MATCHING_RULE_TO_RFC,
        )
        normalized_ordering = attr.ordering
        if attr.ordering:
            normalized_ordering = FlextLdifServersOudConstants.MATCHING_RULE_TO_RFC.get(
                attr.ordering,
                attr.ordering,
            )
        attr = attr.model_copy(
            update={
                "equality": normalized_equality,
                "substr": normalized_substr,
                "ordering": normalized_ordering,
            },
        )
        oid = attr.oid
        oid_validation = self._validate_attribute_oid(oid)
        if oid_validation.failure:
            return r[m.Ldif.SchemaAttribute].fail(
                oid_validation.error or "OID validation failed",
            )
        is_valid_oud_oid = oid_validation.value
        existing_metadata = attr.metadata
        if not existing_metadata:
            existing_metadata = m.Ldif.ServerMetadata.create_for("oud")
        current_extensions = (
            dict(existing_metadata.extensions) if existing_metadata.extensions else {}
        )
        current_extensions[c.Ldif.SYNTAX_OID_VALID] = is_valid_oud_oid
        if oid.endswith("-oid"):
            current_extensions["oid_format_extension"] = True
        attr = attr.model_copy(
            update={
                "metadata": existing_metadata.model_copy(
                    update={"extensions": current_extensions},
                ),
            },
        )
        oud_extensions = self._collect_attribute_extensions(attr)
        if oud_extensions:
            logger.debug(
                "Attribute has OUD X-* extensions",
                attribute_name=attr.name,
                attribute_oid=attr.oid,
                extensions=",".join(oud_extensions),
                extension_count=len(oud_extensions),
            )
        return r[m.Ldif.SchemaAttribute].ok(attr)

    @override
    def _hook_post_parse_objectclass(
        self,
        oc: m.Ldif.SchemaObjectClass,
    ) -> p.Result[m.Ldif.SchemaObjectClass]:
        """Hook: Validate OUD-specific objectClass features after RFC parsing."""
        sup_validation = self._validate_objectclass_sup(oc)
        if sup_validation.failure:
            return r[m.Ldif.SchemaObjectClass].fail(
                sup_validation.error or "SUP validation failed",
            )
        oid_and_sup_validation = self._validate_objectclass_oid_and_sup(oc)
        if oid_and_sup_validation.failure:
            return r[m.Ldif.SchemaObjectClass].fail(
                oid_and_sup_validation.error or "OID validation failed",
            )
        oc = oid_and_sup_validation.value
        sup_str = str(oc.sup) if oc.sup else "none"
        logger.debug(
            "ObjectClass validated: SingleSUP constraint OK",
            objectclass_name=oc.name,
            objectclass_oid=oc.oid,
            sup_value=sup_str,
        )
        return r[m.Ldif.SchemaObjectClass].ok(oc)

    @override
    def _transform_attribute_for_write(
        self,
        attr_data: m.Ldif.SchemaAttribute,
    ) -> m.Ldif.SchemaAttribute:
        """Apply OUD-specific attribute transformations before writing."""
        fixed_equality, fixed_substr = self._transform_by_matching_rules(
            attr_data,
        )
        is_boolean = u.Ldif.is_boolean_attribute(
            attr_data.name,
            set(FlextLdifServersOudConstants.BOOLEAN_ATTRIBUTES),
        )
        if is_boolean:
            logger.debug(
                "Identified boolean attribute",
                attribute_name=attr_data.name,
                attribute_oid=attr_data.oid,
            )
        updated_attr = attr_data.model_copy(
            update={"equality": fixed_equality, "substr": fixed_substr},
        )
        return self._apply_attribute_oid_metadata(updated_attr)

    def _validate_attribute_oid(self, oid: str) -> p.Result[bool]:
        """Validate attribute OID format for OUD."""
        oid_validation_result = u.Ldif.validate_format(oid)
        if oid_validation_result.failure:
            return r[bool].fail_op("OID validation", oid_validation_result.error)
        is_valid_basic_oid = oid_validation_result.value
        is_valid_oud_oid = is_valid_basic_oid
        if not is_valid_oud_oid and oid.endswith("-oid"):
            base_oid = oid[:-4]
            base_validation = u.Ldif.validate_format(base_oid)
            if base_validation.success:
                is_valid_oud_oid = base_validation.value
        if not is_valid_oud_oid:
            return r[bool].fail(
                f"Invalid OUD OID format: {oid} (must be numeric RFC OID or end with -oid suffix)",
            )
        return r[bool].ok(is_valid_oud_oid)

    def _validate_objectclass_oid_and_sup(
        self,
        oc: m.Ldif.SchemaObjectClass,
    ) -> p.Result[m.Ldif.SchemaObjectClass]:
        """Validate ObjectClass OID and SUP OID formats."""
        if oc and oc.oid:
            oid_str = oc.oid
            oid_validation = self._validate_attribute_oid(oid_str)
            if oid_validation.failure:
                return r[m.Ldif.SchemaObjectClass].fail_op(
                    "ObjectClass OID validation", oid_validation.error
                )
            is_valid_oud_oid = oid_validation.value
            existing_oc_metadata = oc.metadata
            if not existing_oc_metadata:
                existing_oc_metadata = m.Ldif.ServerMetadata.create_for("oud")
            oc_extensions = (
                dict(existing_oc_metadata.extensions)
                if existing_oc_metadata.extensions
                else {}
            )
            oc_extensions[c.Ldif.SYNTAX_OID_VALID] = is_valid_oud_oid
            if oid_str.endswith("-oid"):
                oc_extensions["oid_format_extension"] = True
            oc = oc.model_copy(
                update={
                    "metadata": existing_oc_metadata.model_copy(
                        update={"extensions": oc_extensions},
                    ),
                },
            )
        sup = oc.sup
        if sup:
            sup_str = str(sup)
            if sup_str and "." in sup_str and sup_str[0].isdigit():
                sup_validation = self._validate_attribute_oid(sup_str)
                if sup_validation.failure:
                    return r[m.Ldif.SchemaObjectClass].fail_op(
                        "ObjectClass SUP OID validation", sup_validation.error
                    )
        return r[m.Ldif.SchemaObjectClass].ok(oc)

    def _validate_objectclass_sup(self, oc: m.Ldif.SchemaObjectClass) -> p.Result[bool]:
        """Validate objectClass SUP constraint for OUD."""
        sup = oc.sup
        if sup:
            sup_str = str(sup)
            if "$" in sup_str:
                return r[bool].fail(
                    f"OUD objectClass '{oc.name}' has multiple SUPs: {sup_str}. OUD only allows single SUP (use AUXILIARY classes for additional features).",
                )
        return r[bool].ok(value=True)
