"""Extracted nested class from FlextLdifUtilities.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Callable

from flext_core import FlextLogger, FlextResult as r

from flext_ldif._models.domain import FlextLdifModelsDomains
from flext_ldif._utilities.schema import FlextLdifUtilitiesSchema
from flext_ldif.constants import c
from flext_ldif.models import m


class _SchemaConstants:
    """Schema constants container for type safety."""

    AUXILIARY: str
    STRUCTURAL: str

    def __init__(self) -> None:
        """Initialize schema constants from SchemaKind enum."""
        # Use SchemaKind enum values directly (DRY pattern)
        self.AUXILIARY = c.Ldif.SchemaKind.AUXILIARY.value
        self.STRUCTURAL = c.Ldif.SchemaKind.STRUCTURAL.value


# Cache schema constants to avoid repeated getattr calls
# Access at runtime to avoid circular import issues
def _get_schema_constants() -> _SchemaConstants:
    """Get schema constants, accessing at runtime to avoid circular imports."""
    # Use _SchemaConstants class for type safety
    return _SchemaConstants()


logger = FlextLogger(__name__)


class FlextLdifUtilitiesObjectClass:
    """RFC 4512 ObjectClass Validation and Correction Utilities.

    Pure static methods for validating and fixing ObjectClass definitions
    according to RFC 4512. These methods modify FlextLdifModelsDomains.SchemaObjectClass models in-place.

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
        - Type-safe with FlextLdifModelsDomains.SchemaObjectClass
        - Server-agnostic where possible, server-specific where necessary

    Usage:
        >>> from flext_ldif._utilities.object_class import FlextLdifUtilitiesObjectClass
        >>> oc = FlextLdifModelsDomains.SchemaObjectClass(
        ...     name="test", kind="structural"
        ... )
        >>> FlextLdifUtilitiesObjectClass.fix_missing_sup(oc)
        >>> assert oc.sup == "top"
    """

    @staticmethod
    def fix_missing_sup(
        schema_oc: FlextLdifModelsDomains.SchemaObjectClass,
    ) -> None:
        """Fix AUXILIARY ObjectClass missing SUP (superior) attribute.

        RFC 4512 requires all ObjectClasses to have a SUP (superior) except
        for the root "top" class. This method adds "top" as SUP for AUXILIARY
        classes that are missing it. STRUCTURAL classes are left unchanged.

        Args:
            schema_oc: ObjectClass model to potentially fix (modified in-place)

        Returns:
            None - modifies schema_oc in-place

        Business Rules:
            - Only fixes AUXILIARY classes
            - Only fixes if SUP is missing (None or empty)
            - Sets SUP to "top" (RFC 4512 root class)
            - Idempotent (safe to call multiple times)

        """
        schema_constants = _get_schema_constants()
        # Only fix AUXILIARY classes - STRUCTURAL classes are left unchanged
        if schema_oc.kind == schema_constants.AUXILIARY and not schema_oc.sup:
            schema_oc.sup = "top"

    @staticmethod
    def fix_auxiliary_without_sup(
        schema_oc: FlextLdifModelsDomains.SchemaObjectClass,
    ) -> None:
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
        schema_constants = _get_schema_constants()
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
        schema_oc: FlextLdifModelsDomains.SchemaObjectClass,
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

        schema_constants = _get_schema_constants()
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
    def ensure_sup_for_auxiliary(
        schema_oc: FlextLdifModelsDomains.SchemaObjectClass,
        default_sup: str = "top",
    ) -> None:
        """Ensure AUXILIARY ObjectClass has SUP attribute.

        RFC 4512 requires all ObjectClasses (including AUXILIARY) to have a SUP.
        This method adds the specified SUP (default "top") for AUXILIARY classes
        missing it.

        Args:
            schema_oc: ObjectClass model to potentially fix (modified in-place)
            default_sup: Default SUP to use if missing (default: "top")

        Returns:
            None - modifies schema_oc in-place

        Business Rules:
            - Only fixes AUXILIARY classes
            - Sets SUP to default_sup if missing
            - Idempotent (safe to call multiple times)

        """
        schema_constants = _get_schema_constants()
        if schema_oc.kind == schema_constants.AUXILIARY and not schema_oc.sup:
            schema_oc.sup = default_sup

    @staticmethod
    def align_kind_with_superior(
        schema_oc: FlextLdifModelsDomains.SchemaObjectClass,
        superior_kind: str | None,
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
            - Only aligns if schema_oc has a SUP defined
            - Only aligns if superior_kind is provided
            - Sets kind to match superior_kind
            - Idempotent (safe to call multiple times)

        """
        # Only align if:
        # - schema_oc has a SUP defined
        # - schema_oc.kind is not empty (falsy check - empty string means undefined)
        # - superior_kind is provided
        # - current kind differs from superior_kind
        if (
            schema_oc.sup
            and schema_oc.kind
            and superior_kind
            and schema_oc.kind != superior_kind
        ):
            schema_oc.kind = superior_kind

    @staticmethod
    def parse(
        definition: str,
        server_type: str | None = None,
        parse_parts_hook: Callable[[str], dict[str, object]] | None = None,
    ) -> r[m.Ldif.SchemaObjectClass]:
        """Parse RFC 4512 objectClass definition into SchemaObjectClass model.

        Args:
            definition: RFC 4512 objectClass definition string
            server_type: Server type for quirk handling (optional)
            parse_parts_hook: Custom parsing hook (optional)

        Returns:
            FlextResult[SchemaObjectClass] with parsed model or error

        """
        try:
            # Parse to dict first
            parsed_dict = FlextLdifUtilitiesSchema.parse_objectclass(definition)

            # Apply server-specific parsing hook if provided
            if parse_parts_hook is not None:
                # Hook receives the definition and returns parsed dict
                parsed_dict = parse_parts_hook(definition)

            # Extract and validate required fields with type narrowing
            oid_value = parsed_dict.get("oid")
            if not isinstance(oid_value, str):
                return r[m.Ldif.SchemaObjectClass].fail(
                    "Missing or invalid 'oid' field",
                )

            kind_value = parsed_dict.get("kind")
            if not isinstance(kind_value, str):
                return r[m.Ldif.SchemaObjectClass].fail(
                    "Missing or invalid 'kind' field",
                )

            # Extract optional fields with type narrowing
            name_value = parsed_dict.get("name")
            name_str = name_value if isinstance(name_value, str) else ""

            desc_value = parsed_dict.get("desc")
            desc_str = desc_value if isinstance(desc_value, str) else None

            sup_value = parsed_dict.get("sup")
            sup_typed: str | list[str] | None = None
            if isinstance(sup_value, str):
                sup_typed = sup_value
            elif isinstance(sup_value, list):
                sup_typed = [s for s in sup_value if isinstance(s, str)]

            must_value = parsed_dict.get("must")
            must_typed: list[str] | None = None
            if isinstance(must_value, list):
                must_typed = [s for s in must_value if isinstance(s, str)]

            may_value = parsed_dict.get("may")
            may_typed: list[str] | None = None
            if isinstance(may_value, list):
                may_typed = [s for s in may_value if isinstance(s, str)]

            # Create the model with validated types
            schema_oc = m.Ldif.SchemaObjectClass(
                oid=oid_value,
                name=name_str,
                desc=desc_str,
                sup=sup_typed,
                kind=kind_value,
                must=must_typed,
                may=may_typed,
            )

            # Apply fixes based on server type
            if server_type:
                FlextLdifUtilitiesObjectClass.fix_missing_sup(schema_oc)

            return r[m.Ldif.SchemaObjectClass].ok(schema_oc)

        except Exception as e:
            return r[m.Ldif.SchemaObjectClass].fail(
                f"Failed to parse objectClass definition: {e}",
            )
