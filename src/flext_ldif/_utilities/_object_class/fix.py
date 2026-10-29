"""ObjectClass validation and correction utilities.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import TYPE_CHECKING, ClassVar

from flext_ldif import c

if TYPE_CHECKING:
    from flext_ldif._models import FlextLdifModelsDomainSchema


class FlextLdifUtilitiesObjectClassFix:
    """RFC 4512 ObjectClass Validation and Correction operations."""

    AUXILIARY: ClassVar[str] = c.Ldif.SchemaKind.AUXILIARY.value
    STRUCTURAL: ClassVar[str] = c.Ldif.SchemaKind.STRUCTURAL.value

    @classmethod
    def fix_kind_mismatch(
        cls,
        schema_oc: FlextLdifModelsDomainSchema.SchemaObjectClass,
        _server_type: str = "oid",
    ) -> None:
        """Fix objectClass kind mismatches with superior classes (server-specific)."""
        del _server_type
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
        target: FlextLdifModelsDomainSchema.SchemaObjectClass = schema_oc
        if sup_lower in structural_superiors and target.kind == cls.AUXILIARY:
            target.kind = cls.STRUCTURAL
        elif sup_lower in auxiliary_superiors and target.kind == cls.STRUCTURAL:
            target.kind = cls.AUXILIARY

    @classmethod
    def fix_missing_sup(
        cls,
        schema_oc: FlextLdifModelsDomainSchema.SchemaObjectClass,
    ) -> None:
        """Fix AUXILIARY ObjectClass missing SUP (superior) attribute."""
        target: FlextLdifModelsDomainSchema.SchemaObjectClass = schema_oc
        if target.kind == cls.AUXILIARY and (not target.sup):
            target.sup = "top"


__all__: list[str] = ["FlextLdifUtilitiesObjectClassFix"]
