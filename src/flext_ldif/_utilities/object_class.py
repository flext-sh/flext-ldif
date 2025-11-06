"""Extracted nested class from FlextLdifUtilities.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import logging

from flext_ldif.constants import FlextLdifConstants
from flext_ldif.models import FlextLdifModels

logger = logging.getLogger(__name__)


class FlextLdifUtilitiesObjectClass:
    """RFC 4512 ObjectClass Validation and Correction Utilities.

    Pure static methods for validating and fixing ObjectClass definitions
    according to RFC 4512. These methods modify SchemaObjectClass models in-place.

    Used by server quirks during normalization/denormalization to fix common
    ObjectClass issues that violate RFC 4512 compliance.

    ═══════════════════════════════════════════════════════════════════════
    RFC 4512 ObjectClass Requirements

    - AUXILIARY classes MUST have explicit SUP clause
    - ObjectClass kind must match superior class kind (STRUCTURAL vs AUXILIARY)
    - Abstract classes must have SUP (except root abstract classes like "top")

    ═══════════════════════════════════════════════════════════════════════
    Usage Pattern

    These methods are called by server quirks during schema normalization:

        from flext_ldif.utilities import FlextLdifUtilities

        FlextLdifUtilitiesObjectClass.fix_missing_sup(
            schema_oc, server_type="oid"
        )
        FlextLdifUtilitiesObjectClass.fix_kind_mismatch(
            schema_oc, server_type="oid"
        )
        FlextLdifUtilitiesObjectClass.ensure_sup_for_auxiliary(schema_oc)
        FlextLdifUtilitiesObjectClass.align_kind_with_superior(
            schema_oc, superior_kind
        )

    """

    @staticmethod
    def fix_missing_sup(
        schema_oc: FlextLdifModels.SchemaObjectClass,
        server_type: str = "oid",  # noqa: ARG004  # Reserved for server-specific logic
    ) -> None:
        """Fix missing SUP for AUXILIARY objectClasses (server-specific fixes).

        RFC 4512 requires AUXILIARY classes to have explicit SUP clause.
        This method fixes known AUXILIARY classes that are missing SUP,
        using server-specific knowledge.

        For general fixes, use ensure_sup_for_auxiliary() instead.

        Args:
            schema_oc: ObjectClass model to potentially fix (modified in-place)
            server_type: Server type hint for logging (e.g., "oid", "oud") (unused)

        Returns:
            None - modifies schema_oc in-place

        Note:
            Only fixes AUXILIARY classes without SUP. Known problematic
            classes from OID/OUD are fixed automatically. For general cases,
            delegates to ensure_sup_for_auxiliary().

        """
        # Only fix AUXILIARY classes without SUP
        if schema_oc.sup or schema_oc.kind != FlextLdifConstants.Schema.AUXILIARY:
            return

        # Known AUXILIARY classes from OID that are missing SUP top
        auxiliary_without_sup = {
            "orcldAsAttrCategory",  # orclDASAttrCategory
            "orcldasattrcategory",
        }
        name_lower = str(schema_oc.name).lower() if schema_oc.name else ""

        # If it's a known problematic class, fix it
        if name_lower in auxiliary_without_sup:
            schema_oc.sup = "top"
        else:
            # For unknown cases, use general fix
            FlextLdifUtilitiesObjectClass.ensure_sup_for_auxiliary(schema_oc)

    @staticmethod
    def fix_kind_mismatch(
        schema_oc: FlextLdifModels.SchemaObjectClass,
        _server_type: str = "oid",
    ) -> None:
        """Fix objectClass kind mismatches with superior classes (server-specific).

        Some ObjectClasses have kind mismatches with their superior classes
        (e.g., AUXILIARY class with STRUCTURAL superior). This method fixes
        such mismatches using server-specific knowledge.

        For general fixes when you know the superior_kind, use
        align_kind_with_superior() instead.

        Args:
            schema_oc: ObjectClass model to potentially fix (modified in-place)
            _server_type: Server type hint for logging (e.g., "oid", "oud") (unused)

        Returns:
            None - modifies schema_oc in-place

        Note:
            Only fixes if both SUP and kind are present. Known problematic
            superior classes are handled automatically. For general cases,
            requires superior_kind to use align_kind_with_superior().

        """
        # Only fix if both SUP and kind are present
        if not schema_oc.sup or not schema_oc.kind:
            return

        # Known STRUCTURAL superior classes that cause conflicts
        structural_superiors = {
            "orclpwdverifierprofile",
            "orclapplicationentity",
            "tombstone",
        }
        # Known AUXILIARY superior classes that cause conflicts
        auxiliary_superiors = {"javanamingref", "javanamingReference"}

        sup_lower = str(schema_oc.sup).lower() if isinstance(schema_oc.sup, str) else ""

        # If SUP is STRUCTURAL but objectClass is AUXILIARY, change to STRUCTURAL
        if (
            sup_lower in structural_superiors
            and schema_oc.kind == FlextLdifConstants.Schema.AUXILIARY
        ):
            schema_oc.kind = FlextLdifConstants.Schema.STRUCTURAL

        # If SUP is AUXILIARY but objectClass is STRUCTURAL, change to AUXILIARY
        elif (
            sup_lower in auxiliary_superiors
            and schema_oc.kind == FlextLdifConstants.Schema.STRUCTURAL
        ):
            schema_oc.kind = FlextLdifConstants.Schema.AUXILIARY

    @staticmethod
    def ensure_sup_for_auxiliary(
        schema_oc: FlextLdifModels.SchemaObjectClass,
        default_sup: str = "top",
    ) -> None:
        """Ensure AUXILIARY objectClasses have a SUP clause.

        RFC 4512 requires AUXILIARY classes to have explicit SUP.
        If missing, adds the specified default SUP value.

        This is a general method that can be used by all quirks.
        For server-specific fixes, use fix_missing_sup() instead.

        Args:
            schema_oc: ObjectClass model to potentially fix (modified in-place)
            default_sup: Default SUP value to add if missing (default: "top")

        Returns:
            None - modifies schema_oc in-place

        """
        if not schema_oc.sup and schema_oc.kind == FlextLdifConstants.Schema.AUXILIARY:
            schema_oc.sup = default_sup

    @staticmethod
    def align_kind_with_superior(
        schema_oc: FlextLdifModels.SchemaObjectClass,
        superior_kind: str | None,
    ) -> None:
        """Align ObjectClass kind with its superior class kind.

        General method that aligns ObjectClass kind with superior class kind
        for RFC 4512 compliance. This is called by fix_kind_mismatch() for
        known problematic cases, but can also be used directly.

        Args:
            schema_oc: ObjectClass model to potentially fix (modified in-place)
            superior_kind: Kind of the superior ObjectClass

        Returns:
            None - modifies schema_oc in-place

        """
        if not schema_oc.sup or not schema_oc.kind or not superior_kind:
            return

        if (
            superior_kind == FlextLdifConstants.Schema.STRUCTURAL
            and schema_oc.kind == FlextLdifConstants.Schema.AUXILIARY
        ):
            schema_oc.kind = FlextLdifConstants.Schema.STRUCTURAL
        elif (
            superior_kind == FlextLdifConstants.Schema.AUXILIARY
            and schema_oc.kind == FlextLdifConstants.Schema.STRUCTURAL
        ):
            schema_oc.kind = FlextLdifConstants.Schema.AUXILIARY


__all__ = [
    "FlextLdifUtilitiesObjectClass",
]
