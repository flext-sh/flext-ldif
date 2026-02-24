"""Extracted nested class from FlextLdifUtilities."""

from __future__ import annotations

from collections.abc import Callable, Mapping

from pydantic import BaseModel, ConfigDict, Field

from flext_core import FlextLogger, r, u

from flext_ldif._models.domain import FlextLdifModelsDomains
from flext_ldif._utilities.schema import FlextLdifUtilitiesSchema
from flext_ldif.constants import c
from flext_ldif.models import m
from flext_ldif.typings import t


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


class _ParsedObjectClass(BaseModel):
    """Typed payload for parsed objectClass definitions."""

    model_config = ConfigDict(extra="ignore")

    oid: str
    kind: str
    name: str = Field(default="")
    desc: str | None = Field(default=None)
    sup: str | list[str] | None = Field(default=None)
    must: list[str] | None = Field(default=None)
    may: list[str] | None = Field(default=None)


class FlextLdifUtilitiesObjectClass:
    """RFC 4512 ObjectClass Validation and Correction Utilities."""

    @staticmethod
    def fix_missing_sup(
        schema_oc: FlextLdifModelsDomains.SchemaObjectClass,
    ) -> None:
        """Fix AUXILIARY ObjectClass missing SUP (superior) attribute."""
        schema_constants = _get_schema_constants()
        # Only fix AUXILIARY classes - STRUCTURAL classes are left unchanged
        if schema_oc.kind == schema_constants.AUXILIARY and not schema_oc.sup:
            schema_oc.sup = "top"

    @staticmethod
    def fix_kind_mismatch(
        schema_oc: FlextLdifModelsDomains.SchemaObjectClass,
        _server_type: str = "oid",
    ) -> None:
        """Fix objectClass kind mismatches with superior classes (server-specific)."""
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

        sup_lower = (
            schema_oc.sup.lower() if u.Guards.is_type(schema_oc.sup, str) else ""
        )

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
        """Ensure AUXILIARY ObjectClass has SUP attribute."""
        schema_constants = _get_schema_constants()
        if schema_oc.kind == schema_constants.AUXILIARY and not schema_oc.sup:
            schema_oc.sup = default_sup

    @staticmethod
    def align_kind_with_superior(
        schema_oc: FlextLdifModelsDomains.SchemaObjectClass,
        superior_kind: str | None,
    ) -> None:
        """Align ObjectClass kind with its superior class kind."""
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
        parse_parts_hook: Callable[[str], Mapping[str, t.GeneralValueType]]
        | None = None,
    ) -> r[m.Ldif.SchemaObjectClass]:
        """Parse RFC 4512 objectClass definition into SchemaObjectClass model."""
        try:
            # Parse to dict first
            parsed_dict: Mapping[str, t.GeneralValueType] = (
                FlextLdifUtilitiesSchema.parse_objectclass(definition)
            )

            # Apply server-specific parsing hook if provided
            if parse_parts_hook is not None:
                # Hook receives the definition and returns parsed dict
                parsed_dict = parse_parts_hook(definition)

            parsed_model = _ParsedObjectClass.model_validate(parsed_dict)

            # Create the model with validated types
            schema_oc = m.Ldif.SchemaObjectClass(
                oid=parsed_model.oid,
                name=parsed_model.name,
                desc=parsed_model.desc,
                sup=parsed_model.sup,
                kind=parsed_model.kind,
                must=parsed_model.must,
                may=parsed_model.may,
            )

            # Apply fixes based on server type
            if server_type:
                FlextLdifUtilitiesObjectClass.fix_missing_sup(schema_oc)

            return r[m.Ldif.SchemaObjectClass].ok(schema_oc)

        except Exception as e:
            return r[m.Ldif.SchemaObjectClass].fail(
                f"Failed to parse objectClass definition: {e}",
            )
