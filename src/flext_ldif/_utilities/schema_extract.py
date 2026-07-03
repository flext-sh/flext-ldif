"""Schema-definition extraction helpers for FLEXT-LDIF."""

from __future__ import annotations

from collections.abc import Callable

from flext_ldif import c, p, r, t
from flext_ldif._utilities.parser import FlextLdifUtilitiesParser as up
from flext_ldif.models import FlextLdifModels as m


class FlextLdifUtilitiesSchemaExtract:
    """Extract RFC 4512 schema fields from raw definition strings."""

    @staticmethod
    def extract_attribute_flags(attr_definition: str) -> tuple[bool, bool]:
        """Extract boolean flags (single_value, no_user_modification) from attribute definition."""
        single_value = up.extract_boolean_flag(
            attr_definition,
            c.Ldif.SCHEMA_SINGLE_VALUE,
        )
        no_user_modification = up.extract_boolean_flag(
            attr_definition,
            c.Ldif.SCHEMA_NO_USER_MODIFICATION,
        )
        return (single_value, no_user_modification)

    @staticmethod
    def extract_attribute_matching_rules(
        attr_definition: str,
    ) -> tuple[str | None, str | None, str | None]:
        """Extract matching rules (equality, substr, ordering) from attribute definition."""
        equality = up.extract_optional_field(
            attr_definition,
            c.Ldif.SCHEMA_EQUALITY,
        )
        substr = up.extract_optional_field(
            attr_definition,
            c.Ldif.SCHEMA_SUBSTR,
        )
        ordering = up.extract_optional_field(
            attr_definition,
            c.Ldif.SCHEMA_ORDERING,
        )
        return (equality, substr, ordering)

    @staticmethod
    def extract_attribute_sup_usage(
        attr_definition: str,
    ) -> tuple[str | None, str | None]:
        """Extract SUP and USAGE from attribute definition."""
        sup = up.extract_optional_field(
            attr_definition,
            c.Ldif.SCHEMA_SUP,
        )
        usage = up.extract_optional_field(
            attr_definition,
            c.Ldif.SCHEMA_USAGE,
        )
        return (sup, usage)

    @staticmethod
    def extract_attribute_syntax(
        attr_definition: str,
    ) -> tuple[str | None, int | None]:
        """Extract SYNTAX and length from attribute definition."""
        syntax_match = c.Ldif.SCHEMA_SYNTAX_LENGTH_RE.search(attr_definition)
        syntax = syntax_match.group(1) if syntax_match else None
        length = (
            int(syntax_match.group(2))
            if syntax_match and syntax_match.group(2)
            else None
        )
        return (syntax, length)

    @staticmethod
    def extract_objectclass_kind(oc_definition: str) -> str:
        """Extract KIND from objectClass definition."""
        kind_match = c.Ldif.SCHEMA_OBJECTCLASS_KIND_RE.search(oc_definition)
        return (
            kind_match.group(1).upper()
            if kind_match
            else c.Ldif.SchemaKind.STRUCTURAL.value
        )

    @staticmethod
    def extract_objectclass_must_may(
        oc_definition: str,
    ) -> tuple[t.MutableSequenceOf[str] | None, t.MutableSequenceOf[str] | None]:
        """Extract MUST and MAY attributes from objectClass definition."""
        must = None
        must_match = c.Ldif.SCHEMA_OBJECTCLASS_MUST_RE.search(oc_definition)
        if must_match:
            must_value = (must_match.group(1) or must_match.group(2)).strip()
            must = FlextLdifUtilitiesSchemaExtract.split_schema_values(must_value)
        may = None
        may_match = c.Ldif.SCHEMA_OBJECTCLASS_MAY_RE.search(oc_definition)
        if may_match:
            may_value = (may_match.group(1) or may_match.group(2)).strip()
            may = FlextLdifUtilitiesSchemaExtract.split_schema_values(may_value)
        return (must, may)

    @staticmethod
    def extract_objectclass_sup(oc_definition: str) -> str | None:
        """Extract SUP from objectClass definition."""
        sup_match = c.Ldif.SCHEMA_OBJECTCLASS_SUP_RE.search(oc_definition)
        if not sup_match:
            return None
        sup_value = sup_match.group(1) or sup_match.group(2) or sup_match.group(3)
        return f"{sup_value}".strip().split("$", maxsplit=1)[0].strip()

    @staticmethod
    def extract_schema_basic_fields(
        definition: str,
        definition_label: str,
    ) -> p.Result[tuple[str, str, str | None]]:
        oid_result = up.extract_oid(definition)
        if oid_result.failure:
            error = oid_result.error or "unknown OID extraction error"
            return r[tuple[str, str, str | None]].fail(
                f"RFC {definition_label} parsing failed: {error}",
            )
        if not oid_result.success:
            return r[tuple[str, str, str | None]].fail(
                f"RFC {definition_label} parsing failed: unknown result state",
            )
        oid = oid_result.value
        name_raw = up.extract_optional_field(
            definition,
            c.Ldif.SCHEMA_NAME,
            default=oid,
        )
        name: str = name_raw if name_raw is not None else oid
        desc = up.extract_optional_field(
            definition,
            c.Ldif.SCHEMA_DESC,
        )
        return r[tuple[str, str, str | None]].ok((oid, name, desc))

    @staticmethod
    def extract_schema_items_from_lines[SchemaModelT: m.Ldif.SchemaElement](
        ldif_content: str,
        parse_callback: Callable[[str], p.Result[SchemaModelT]],
        line_prefix: str,
        model_type: type[SchemaModelT],
    ) -> t.MutableSequenceOf[SchemaModelT]:
        """Generic extraction of schema items from LDIF content lines."""
        items: t.MutableSequenceOf[SchemaModelT] = []
        for raw_line in ldif_content.split("\n"):
            line = raw_line.strip()
            if line.lower().startswith(line_prefix.lower()):
                item_def = line.split(":", 1)[1].strip()
                result = parse_callback(item_def)
                if result.success:
                    try:
                        items.append(model_type.model_validate(result.value))
                    except c.Ldif.EXC_LDIF_PARSE:
                        continue
        return items

    @staticmethod
    def split_schema_values(value: str) -> t.MutableSequenceOf[str]:
        return [item.strip() for item in value.strip().split("$")]


__all__: list[str] = ["FlextLdifUtilitiesSchemaExtract"]
