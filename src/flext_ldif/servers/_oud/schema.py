"""Oracle Unified Directory (OUD) Quirks."""

from __future__ import annotations

from flext_core import FlextLogger, FlextResult, FlextService

from flext_ldif._utilities.schema import FlextLdifUtilitiesSchema
from flext_ldif.constants import c
from flext_ldif.models import m
from flext_ldif.servers._oud.constants import FlextLdifServersOudConstants
from flext_ldif.servers.rfc import FlextLdifServersRfc
from flext_ldif.utilities import u

logger = FlextLogger(__name__)


class FlextLdifServersOudSchema(FlextLdifServersRfc.Schema):
    """Oracle OUD Schema Implementation (RFC 4512 + OUD Extensions)."""

    def __init__(
        self,
        schema_service: object | None = None,
        **kwargs: str | float | bool | None,
    ) -> None:
        """Initialize OUD schema quirk."""
        filtered_kwargs: dict[str, str | float | bool | None] = {
            k: v
            for k, v in kwargs.items()
            if k not in ("_parent_quirk", "_schema_service")
            and isinstance(v, (str, float, bool, type(None)))
        }

        FlextService.__init__(self, **filtered_kwargs)

        if schema_service is not None:
            object.__setattr__(self, "_schema_service", schema_service)

    def _validate_attribute_oid(
        self,
        oid: str,
    ) -> FlextResult[bool]:
        """Validate attribute OID format for OUD."""
        oid_validation_result = u.Ldif.OID.validate_format(oid)
        if oid_validation_result.is_failure:
            return FlextResult[bool].fail(
                f"OID validation failed: {oid_validation_result.error}",
            )

        is_valid_basic_oid = oid_validation_result.value

        is_valid_oud_oid = is_valid_basic_oid
        if not is_valid_oud_oid and oid.endswith("-oid"):
            base_oid = oid[:-4]
            base_validation = u.Ldif.OID.validate_format(base_oid)
            if base_validation.is_success:
                is_valid_oud_oid = base_validation.value

        if not is_valid_oud_oid:
            return FlextResult[bool].fail(
                f"Invalid OUD OID format: {oid} (must be numeric RFC OID or end with -oid suffix)",
            )

        return FlextResult[bool].ok(is_valid_oud_oid)

    def _collect_attribute_extensions(
        self,
        attr: m.Ldif.SchemaAttribute,
    ) -> list[str]:
        """Collect OUD X-* extensions from attribute."""
        extensions = []
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

    def _hook_post_parse_attribute(
        self,
        attr: m.Ldif.SchemaAttribute,
    ) -> FlextResult[m.Ldif.SchemaAttribute]:
        """Hook: Validate OUD-specific attribute features after RFC parsing."""
        if not attr or not attr.oid:
            return FlextResult[m.Ldif.SchemaAttribute].ok(attr)

        oid = str(attr.oid)

        oid_validation = self._validate_attribute_oid(oid)
        if oid_validation.is_failure:
            return FlextResult[m.Ldif.SchemaAttribute].fail(
                oid_validation.error or "OID validation failed",
            )

        is_valid_oud_oid = oid_validation.value

        existing_metadata = attr.metadata
        if not existing_metadata:
            existing_metadata = m.Ldif.QuirkMetadata.create_for("oud")

        current_extensions = (
            dict(existing_metadata.extensions) if existing_metadata.extensions else {}
        )

        current_extensions[c.Ldif.MetadataKeys.SYNTAX_OID_VALID] = is_valid_oud_oid

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
                extensions=oud_extensions,
                extension_count=len(oud_extensions),
            )

        return FlextResult[m.Ldif.SchemaAttribute].ok(attr)

    def _validate_objectclass_sup(
        self,
        oc: m.Ldif.SchemaObjectClass,
    ) -> FlextResult[bool]:
        """Validate objectClass SUP constraint for OUD."""
        sup = oc.sup
        if sup:
            sup_str = str(sup)

            if "$" in sup_str:
                return FlextResult[bool].fail(
                    f"OUD objectClass '{oc.name}' has multiple SUPs: "
                    f"{sup_str}. "
                    "OUD only allows single SUP (use AUXILIARY classes "
                    "for additional features).",
                )
        return FlextResult[bool].ok(True)

    def _validate_objectclass_oid_and_sup(
        self,
        oc: m.Ldif.SchemaObjectClass,
    ) -> FlextResult[m.Ldif.SchemaObjectClass]:
        """Validate ObjectClass OID and SUP OID formats."""
        if oc and oc.oid:
            oid_str = str(oc.oid)
            oid_validation = self._validate_attribute_oid(oid_str)
            if oid_validation.is_failure:
                return FlextResult[m.Ldif.SchemaObjectClass].fail(
                    f"ObjectClass OID validation failed: {oid_validation.error}",
                )

            is_valid_oud_oid = oid_validation.value

            existing_oc_metadata = oc.metadata
            if not existing_oc_metadata:
                existing_oc_metadata = m.Ldif.QuirkMetadata.create_for(
                    "oud",
                )

            oc_extensions = (
                dict(existing_oc_metadata.extensions)
                if existing_oc_metadata.extensions
                else {}
            )

            oc_extensions[c.Ldif.MetadataKeys.SYNTAX_OID_VALID] = is_valid_oud_oid

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
                if sup_validation.is_failure:
                    return FlextResult[m.Ldif.SchemaObjectClass].fail(
                        f"ObjectClass SUP OID validation failed: {sup_validation.error}",
                    )

        return FlextResult[m.Ldif.SchemaObjectClass].ok(oc)

    def _hook_post_parse_objectclass(
        self,
        oc: m.Ldif.SchemaObjectClass,
    ) -> FlextResult[m.Ldif.SchemaObjectClass]:
        """Hook: Validate OUD-specific objectClass features after RFC parsing."""
        if not oc:
            return FlextResult[m.Ldif.SchemaObjectClass].fail(
                "ObjectClass is None or empty",
            )

        sup_validation = self._validate_objectclass_sup(oc)
        if sup_validation.is_failure:
            return FlextResult[m.Ldif.SchemaObjectClass].fail(
                sup_validation.error or "SUP validation failed",
            )

        oid_and_sup_validation = self._validate_objectclass_oid_and_sup(oc)
        if oid_and_sup_validation.is_failure:
            return FlextResult[m.Ldif.SchemaObjectClass].fail(
                oid_and_sup_validation.error or "OID validation failed",
            )

        oc = oid_and_sup_validation.value

        logger.debug(
            "ObjectClass validated: SingleSUP constraint OK",
            objectclass_name=oc.name,
            objectclass_oid=oc.oid,
            sup_value=oc.sup,
        )

        return FlextResult[m.Ldif.SchemaObjectClass].ok(oc)

    def _apply_attribute_matching_rule_transforms(
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

        if (
            fixed_substr == "caseIgnoreSubstringsMatch"
            and fixed_equality == "caseIgnoreMatch"
        ):
            logger.warning(
                "OUD QUIRK: FOUND REDUNDANT EQUALITY+SUBSTR - Removing redundant EQUALITY",
                attribute_name=attr_data.name,
                attribute_oid=attr_data.oid,
                original_equality=fixed_equality,
                original_substr=fixed_substr,
                new_equality=None,
                new_substr="caseIgnoreSubstringsMatch",
                redundant_equality="caseIgnoreMatch",
            )
            fixed_equality = None

        original_substr = fixed_substr
        fixed_substr = FlextLdifUtilitiesSchema.replace_invalid_substr_rule(
            fixed_substr,
            FlextLdifServersOudConstants.INVALID_SUBSTR_RULES,
        )
        if fixed_substr != original_substr:
            logger.warning(
                "Replaced invalid SUBSTR rule",
                attribute_name=attr_data.name,
                attribute_oid=attr_data.oid,
                original_substr=original_substr,
                replacement_substr=fixed_substr,
            )

        return fixed_equality, fixed_substr

    def _apply_attribute_oid_metadata(
        self,
        attr: m.Ldif.SchemaAttribute,
    ) -> m.Ldif.SchemaAttribute:
        """Apply OID validation and tracking metadata to attribute."""
        if not attr or not attr.oid:
            return attr

        oid_str = str(attr.oid)
        oid_validation = self._validate_attribute_oid(oid_str)
        if oid_validation.is_failure:
            return attr

        is_valid_oud_oid = oid_validation.value

        existing_metadata = attr.metadata
        if not existing_metadata:
            existing_metadata = m.Ldif.QuirkMetadata.create_for("oud")

        current_extensions = (
            dict(existing_metadata.extensions) if existing_metadata.extensions else {}
        )

        current_extensions[c.Ldif.MetadataKeys.SYNTAX_OID_VALID] = is_valid_oud_oid

        if oid_str.endswith("-oid"):
            current_extensions["oid_format_extension"] = True

        return attr.model_copy(
            update={
                "metadata": existing_metadata.model_copy(
                    update={"extensions": current_extensions},
                ),
            },
        )

    def _transform_attribute_for_write(
        self,
        attr_data: m.Ldif.SchemaAttribute,
    ) -> m.Ldif.SchemaAttribute:
        """Apply OUD-specific attribute transformations before writing."""
        fixed_equality, fixed_substr = self._apply_attribute_matching_rule_transforms(
            attr_data,
        )

        is_boolean = FlextLdifUtilitiesSchema.is_boolean_attribute(
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
            update={
                "equality": fixed_equality,
                "substr": fixed_substr,
            },
        )

        return self._apply_attribute_oid_metadata(updated_attr)

    def extract_schemas_from_ldif(
        self,
        ldif_content: str,
        *,
        validate_dependencies: bool = True,
    ) -> FlextResult[
        dict[
            str,
            list[m.Ldif.SchemaAttribute] | list[m.Ldif.SchemaObjectClass],
        ]
    ]:
        """Extract and parse all schema definitions from LDIF content."""
        return super().extract_schemas_from_ldif(
            ldif_content,
            validate_dependencies=validate_dependencies,
        )
