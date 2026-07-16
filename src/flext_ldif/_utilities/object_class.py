"""Extracted nested class from FlextLdifUtilities."""

from __future__ import annotations

from flext_ldif import c, p


class FlextLdifUtilitiesObjectClass:
    """RFC 4512 ObjectClass Validation and Correction Utilities."""

    class SchemaConstants:
        """Schema constants container for type safety (single class, no loose helpers)."""

        auxiliary: str = c.Ldif.SchemaKind.AUXILIARY.value
        structural: str = c.Ldif.SchemaKind.STRUCTURAL.value

    @staticmethod
    def fix_kind_mismatch(
        schema_oc: p.Ldif.SchemaObjectClass,
    ) -> p.Ldif.SchemaObjectClass:
        """Return an ObjectClass with the kind corrected for its superior.

        Pydantic-2-way immutable transition (no in-place mutation): returns the
        corrected ``model_copy`` or the same object when no fix applies.
        """
        if not schema_oc.sup or not schema_oc.kind:
            return schema_oc
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
            return schema_oc.model_copy(update={"kind": schema_constants.structural})
        if (
            sup_lower in auxiliary_superiors
            and schema_oc.kind == schema_constants.structural
        ):
            return schema_oc.model_copy(update={"kind": schema_constants.auxiliary})
        return schema_oc

    @staticmethod
    def fix_missing_sup(
        schema_oc: p.Ldif.SchemaObjectClass,
    ) -> p.Ldif.SchemaObjectClass:
        """Return an AUXILIARY ObjectClass with a default SUP when missing.

        Pydantic-2-way immutable transition (no in-place mutation).
        """
        schema_constants = FlextLdifUtilitiesObjectClass.SchemaConstants
        if schema_oc.kind == schema_constants.auxiliary and (not schema_oc.sup):
            return schema_oc.model_copy(update={"sup": "top"})
        return schema_oc
