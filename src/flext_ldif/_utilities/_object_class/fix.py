"""ObjectClass validation and correction utilities.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import ClassVar

from flext_ldif import c, m, p


class FlextLdifUtilitiesObjectClassFix:
    """RFC 4512 ObjectClass Validation and Correction operations."""

    AUXILIARY: ClassVar[str] = c.Ldif.SchemaKind.AUXILIARY.value
    STRUCTURAL: ClassVar[str] = c.Ldif.SchemaKind.STRUCTURAL.value

    @classmethod
    def fix_kind_mismatch(
        cls,
        schema_oc: p.Ldif.SchemaObjectClass,
        _server_type: str = "oid",
    ) -> p.Ldif.SchemaObjectClass:
        """Fix objectClass kind mismatches with superior classes (server-specific).

        Returns:
            The corrected objectClass.

        """
        del _server_type
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
        target = m.Ldif.SchemaObjectClass.model_validate(schema_oc.model_dump())
        if sup_lower in structural_superiors and target.kind == cls.AUXILIARY:
            target.kind = cls.STRUCTURAL
        elif sup_lower in auxiliary_superiors and target.kind == cls.STRUCTURAL:
            target.kind = cls.AUXILIARY
        return target

    @classmethod
    def fix_missing_sup(
        cls,
        schema_oc: p.Ldif.SchemaObjectClass,
    ) -> p.Ldif.SchemaObjectClass:
        """Fix AUXILIARY ObjectClass missing SUP (superior) attribute.

        Returns:
            The corrected objectClass.

        """
        target = m.Ldif.SchemaObjectClass.model_validate(schema_oc.model_dump())
        if target.kind == cls.AUXILIARY and (not target.sup):
            target.sup = "top"
        return target


__all__: list[str] = ["FlextLdifUtilitiesObjectClassFix"]
