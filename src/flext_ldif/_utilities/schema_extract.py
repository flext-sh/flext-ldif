"""Schema-definition extraction helpers for FLEXT-LDIF.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import TYPE_CHECKING, ClassVar

from flext_cli import u

from flext_ldif import FlextLdifModels, c, p, r, t
from flext_ldif._utilities import FlextLdifUtilitiesParser

if TYPE_CHECKING:
    from collections.abc import Callable


class FlextLdifUtilitiesSchemaExtract:
    """Extract RFC 4512 schema fields from raw definition strings."""

    logger: ClassVar[p.Logger] = u.fetch_logger(__name__)

    @staticmethod
    def extract_attribute_flags(attr_definition: str) -> tuple[bool, bool]:
        """Extract boolean flags (single_value, no_user_modification) from attribute.

        # definition.

        Returns:
            The resulting ``tuple[bool, bool]``.

        """
        single_value = FlextLdifUtilitiesParser.extract_boolean_flag(
            attr_definition,
            c.Ldif.SCHEMA_SINGLE_VALUE,
        )
        no_user_modification = FlextLdifUtilitiesParser.extract_boolean_flag(
            attr_definition,
            c.Ldif.SCHEMA_NO_USER_MODIFICATION,
        )
        return (single_value, no_user_modification)

    @staticmethod
    def extract_attribute_matching_rules(
        attr_definition: str,
    ) -> tuple[str | None, str | None, str | None]:
        """Extract matching rules (equality, substr, ordering) from attribute.

        # definition.

        Returns:
            The resulting ``tuple[str | None, str | None, str | None]``.

        """
        equality = FlextLdifUtilitiesParser.extract_optional_field(
            attr_definition, c.Ldif.SCHEMA_EQUALITY
        )
        substr = FlextLdifUtilitiesParser.extract_optional_field(
            attr_definition, c.Ldif.SCHEMA_SUBSTR
        )
        ordering = FlextLdifUtilitiesParser.extract_optional_field(
            attr_definition, c.Ldif.SCHEMA_ORDERING
        )
        return (equality, substr, ordering)

    @staticmethod
    def extract_attribute_sup_usage(
        attr_definition: str,
    ) -> tuple[str | None, str | None]:
        """Extract SUP and USAGE from attribute definition.

        Returns:
            The resulting ``tuple[str | None, str | None]``.

        """
        sup = FlextLdifUtilitiesParser.extract_optional_field(
            attr_definition, c.Ldif.SCHEMA_SUP
        )
        usage = FlextLdifUtilitiesParser.extract_optional_field(
            attr_definition, c.Ldif.SCHEMA_USAGE
        )
        return (sup, usage)

    @staticmethod
    def extract_attribute_syntax(attr_definition: str) -> tuple[str | None, int | None]:
        """Extract SYNTAX and length from attribute definition.

        Returns:
            The resulting ``tuple[str | None, int | None]``.

        """
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
        """Extract KIND from objectClass definition.

        Returns:
            The resulting ``str``.

        """
        kind_match = c.Ldif.SCHEMA_OBJECTCLASS_KIND_RE.search(oc_definition)
        if kind_match is None:
            return str(c.Ldif.SchemaKind.STRUCTURAL.value)
        kind = kind_match.group(1)
        if kind is None:
            return str(c.Ldif.SchemaKind.STRUCTURAL.value)
        return str(kind).upper()

    @staticmethod
    def extract_objectclass_must_may(
        oc_definition: str,
        *,
        must_separator: str = c.Ldif.SCHEMA_VALUE_SEPARATOR,
        may_separator: str = c.Ldif.SCHEMA_VALUE_SEPARATOR,
    ) -> tuple[t.MutableSequenceOf[str] | None, t.MutableSequenceOf[str] | None]:
        """Extract MUST and MAY attributes from objectClass definition.

        Returns:
            The resulting ``tuple[t.MutableSequenceOf[str] | None,
                t.MutableSequenceOf[str] | None]``.

        """
        must, may = (
            FlextLdifUtilitiesSchemaExtract.split_schema_values(
                match.group(1) or match.group(2),
                separator=separator,
            )
            if (match := pattern.search(oc_definition))
            else None
            for pattern, separator in (
                (c.Ldif.SCHEMA_OBJECTCLASS_MUST_RE, must_separator),
                (c.Ldif.SCHEMA_OBJECTCLASS_MAY_RE, may_separator),
            )
        )
        return (must, may)

    @staticmethod
    def extract_objectclass_sup(oc_definition: str) -> str | None:
        """Extract SUP from objectClass definition.

        Returns:
            The resulting ``str | None``.

        """
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
        oid_result = FlextLdifUtilitiesParser.extract_oid(definition)
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
        name_raw = FlextLdifUtilitiesParser.extract_optional_field(
            definition,
            c.Ldif.SCHEMA_NAME,
            default=oid,
        )
        name: str = name_raw if name_raw is not None else oid
        desc = FlextLdifUtilitiesParser.extract_optional_field(
            definition, c.Ldif.SCHEMA_DESC
        )
        return r[tuple[str, str, str | None]].ok((oid, name, desc))

    @staticmethod
    def extract_schema_items_from_lines[
        SchemaModelT: FlextLdifModels.Ldif.SchemaElement,
    ](
        ldif_content: str,
        parse_callback: Callable[[str], p.Result[SchemaModelT]],
        line_prefix: str,
        model_type: type[SchemaModelT],
    ) -> t.MutableSequenceOf[SchemaModelT]:
        """Extract schema items from LDIF content lines.

        Returns:
            The resulting ``t.MutableSequenceOf[SchemaModelT]``.

        """
        items: t.MutableSequenceOf[SchemaModelT] = []
        for raw_line in ldif_content.split("\n"):
            line = raw_line.strip()
            if line.lower().startswith(line_prefix.lower()):
                item_def = line.split(":", 1)[1].strip()
                result = parse_callback(item_def)
                if result.success:
                    try:
                        items.append(model_type.model_validate(result.value))
                    except c.Ldif.EXC_LDIF_PARSE as exc:
                        FlextLdifUtilitiesSchemaExtract.logger.warning(
                            f"Skipping unparseable schema item on {line!r}: {exc}",
                        )
                        continue
        return items

    @staticmethod
    def split_schema_values(
        value: str,
        *,
        separator: str = c.Ldif.SCHEMA_VALUE_SEPARATOR,
    ) -> t.MutableSequenceOf[str]:
        return [item.strip() for item in value.strip().split(separator)]


__all__: list[str] = ["FlextLdifUtilitiesSchemaExtract"]
