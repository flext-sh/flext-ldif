"""Extracted nested class from FlextLdifUtilities."""

from __future__ import annotations

from flext_ldif import FlextLdifModels as m, c


class FlextLdifUtilitiesObjectClass:
    """RFC 4512 ObjectClass Validation and Correction Utilities."""

    class SchemaConstants:
        """Schema constants container for type safety (single class, no loose helpers)."""

        auxiliary: str = c.Ldif.SchemaKind.AUXILIARY.value
        structural: str = c.Ldif.SchemaKind.STRUCTURAL.value

    @staticmethod
    def fix_kind_mismatch(
        schema_oc: m.Ldif.SchemaObjectClass,
        _server_type: str = "oid",
    ) -> None:
        """Fix objectClass kind mismatches with superior classes (server-specific)."""
        if not schema_oc.sup or not schema_oc.kind:
            return
        structural_superiors = {
            "orclpwdverifierprofile",
            "orclapplicationentity",
            "tombstone",
        }
        auxiliary_superiors = {"javanamingref", "javanamingReference"}
        sup_value = schema_oc.sup
        if isinstance(sup_value, str):
            sup_lower = sup_value.lower() if sup_value else ""
        else:
            first_sup = sup_value[0] if sup_value else ""
            sup_lower = first_sup.lower() if first_sup else ""
        schema_constants = FlextLdifUtilitiesObjectClass.SchemaConstants
        if (
            sup_lower in structural_superiors
            and schema_oc.kind == schema_constants.auxiliary
        ):
            object.__setattr__(schema_oc, "kind", schema_constants.structural)
        elif (
            sup_lower in auxiliary_superiors
            and schema_oc.kind == schema_constants.structural
        ):
            object.__setattr__(schema_oc, "kind", schema_constants.auxiliary)

    @staticmethod
    def fix_missing_sup(
        schema_oc: m.Ldif.SchemaObjectClass,
    ) -> None:
        """Fix AUXILIARY ObjectClass missing SUP (superior) attribute."""
        schema_constants = FlextLdifUtilitiesObjectClass.SchemaConstants
        if schema_oc.kind == schema_constants.auxiliary and (not schema_oc.sup):
            object.__setattr__(schema_oc, "sup", "top")
