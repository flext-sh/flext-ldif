"""Extracted nested class from FlextLdifUtilities.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_core import FlextLogger

from flext_ldif.constants import c
from flext_ldif.models import m

# REMOVED: Type aliases redundantes - use m.Ldif.* diretamente (já importado com runtime alias)
# SchemaObjectClass: TypeAlias = FlextLdifModelsDomains.SchemaObjectClass  # Use m.Ldif.SchemaObjectClass directly


class _SchemaConstants:
    """Schema constants container for type safety."""

    AUXILIARY: str
    STRUCTURAL: str

    def __init__(self) -> None:
        """Initialize schema constants from Format constants."""
        # Constants are at Format level, not Format.Rfc level
        # Access directly without type: ignore (prohibited)
        self.AUXILIARY = c.Ldif.Format.SCHEMA_KIND_AUXILIARY
        self.STRUCTURAL = c.Ldif.Format.SCHEMA_KIND_STRUCTURAL


# Cache schema constants to avoid repeated getattr calls
# Access at runtime to avoid circular import issues
def _get_schema_constants() -> _SchemaConstants:
    """Get schema constants, accessing at runtime to avoid circular imports."""
    # Use _SchemaConstants class for type safety
    return _SchemaConstants()


_schema_constants = _get_schema_constants

logger = FlextLogger(__name__)


class FlextLdifUtilitiesObjectClass:
    """RFC 4512 ObjectClass Validation and Correction Utilities.

    Pure static methods for validating and fixing ObjectClass definitions
    according to RFC 4512. These methods modify m.Ldif.SchemaObjectClass models in-place.

    All methods are static to enable use without instantiation and to avoid
    circular dependencies. Methods are organized by validation/correction type.

    Business Rules:
        - All fixes are applied in-place (modify input model)
        - Fixes preserve existing valid data (no overwrites)
        - Server-specific fixes are clearly marked
        - All fixes are idempotent (safe to call multiple times)

    Architecture:
        - Pure functions (no state, no side effects except model modification)
        - Static methods for easy import and use
        - Type-safe with m.Ldif.SchemaObjectClass
        - Server-agnostic where possible, server-specific where necessary

    Usage:
        >>> from flext_ldif._utilities.object_class import FlextLdifUtilitiesObjectClass
        >>> oc = m.Ldif.SchemaObjectClass(name="test", kind="structural")
        >>> FlextLdifUtilitiesObjectClass.fix_missing_sup(oc)
        >>> assert oc.sup == "top"
    """

    @staticmethod
    def fix_missing_sup(schema_oc: m.Ldif.SchemaObjectClass) -> None:
        """Fix ObjectClass missing SUP (superior) attribute.

        RFC 4512 requires all ObjectClasses to have a SUP (superior) except
        for the root "top" class. This method adds "top" as SUP for classes
        that are missing it.

        Args:
            schema_oc: ObjectClass model to potentially fix (modified in-place)

        Returns:
            None - modifies schema_oc in-place

        Business Rules:
            - Only fixes if SUP is missing (None or empty)
            - Sets SUP to "top" (RFC 4512 root class)
            - Idempotent (safe to call multiple times)

        """
        if not schema_oc.sup:
            schema_oc.sup = "top"

    @staticmethod
    def fix_auxiliary_without_sup(schema_oc: m.Ldif.SchemaObjectClass) -> None:
        """Fix AUXILIARY ObjectClass missing SUP (server-specific fix).

        Some servers (OID/OUD) have AUXILIARY classes without SUP. This method
        fixes known problematic classes and delegates to ensure_sup_for_auxiliary()
        for general cases.

        Args:
            schema_oc: ObjectClass model to potentially fix (modified in-place)

        Returns:
            None - modifies schema_oc in-place

        Note:
            Only fixes AUXILIARY classes. Known problematic classes from OID/OUD
            are fixed automatically. For general cases,
            delegates to ensure_sup_for_auxiliary().

        """
        # Only fix AUXILIARY classes without SUP
        schema_constants = _schema_constants()
        if schema_oc.sup or schema_oc.kind != schema_constants.AUXILIARY:
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
        schema_oc: m.Ldif.SchemaObjectClass,
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

        schema_constants = _schema_constants()
        # If SUP is STRUCTURAL but objectClass is AUXILIARY, change to STRUCTURAL
        if (
            sup_lower in structural_superiors
            and schema_oc.kind == schema_constants.AUXILIARY
        ):
            schema_oc.kind = schema_constants.STRUCTURAL

        # If SUP is AUXILIARY but objectClass is STRUCTURAL, change to AUXILIARY
        elif (
            sup_lower in auxiliary_superiors
            and schema_oc.kind == schema_constants.STRUCTURAL
        ):
            schema_oc.kind = schema_constants.AUXILIARY

    @staticmethod
    def ensure_sup_for_auxiliary(schema_oc: m.Ldif.SchemaObjectClass) -> None:
        """Ensure AUXILIARY ObjectClass has SUP attribute.

        RFC 4512 requires all ObjectClasses (including AUXILIARY) to have a SUP.
        This method adds "top" as SUP for AUXILIARY classes missing it.

        Args:
            schema_oc: ObjectClass model to potentially fix (modified in-place)

        Returns:
            None - modifies schema_oc in-place

        Business Rules:
            - Only fixes AUXILIARY classes
            - Sets SUP to "top" if missing
            - Idempotent (safe to call multiple times)

        """
        schema_constants = _schema_constants()
        if schema_oc.kind == schema_constants.AUXILIARY and not schema_oc.sup:
            schema_oc.sup = "top"

    @staticmethod
    def align_kind_with_superior(
        schema_oc: m.Ldif.SchemaObjectClass,
        superior_kind: str,
    ) -> None:
        """Align ObjectClass kind with its superior class kind.

        Some ObjectClasses have kind mismatches with their superior classes.
        This method aligns the kind to match the superior when provided.

        Args:
            schema_oc: ObjectClass model to potentially fix (modified in-place)
            superior_kind: Kind of the superior class (e.g., "structural", "auxiliary")

        Returns:
            None - modifies schema_oc in-place

        Business Rules:
            - Only aligns if superior_kind is provided
            - Sets kind to match superior_kind
            - Idempotent (safe to call multiple times)

        """
        if superior_kind and schema_oc.kind != superior_kind:
            schema_oc.kind = superior_kind
