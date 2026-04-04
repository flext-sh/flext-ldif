"""Extracted nested class from FlextLdifUtilities."""

from __future__ import annotations

from flext_core import FlextLogger
from flext_ldif._models.domain_entries import FlextLdifModelsDomainsEntries
from flext_ldif.constants import FlextLdifConstants as c

logger = FlextLogger(__name__)


class FlextLdifUtilitiesObjectClass:
    """RFC 4512 ObjectClass Validation and Correction Utilities."""

    class _SchemaConstants:
        """Schema constants container for type safety (single class, no loose helpers)."""

        _instance: FlextLdifUtilitiesObjectClass._SchemaConstants | None = None
        auxiliary: str
        structural: str

        def __init__(self) -> None:
            """Initialize schema constants from SchemaKind enum."""
            super().__init__()
            self.auxiliary = c.Ldif.SchemaKind.AUXILIARY.value
            self.structural = c.Ldif.SchemaKind.STRUCTURAL.value

        @classmethod
        def get_instance(cls) -> FlextLdifUtilitiesObjectClass._SchemaConstants:
            """Return cached schema constants instance (avoids repeated getattr)."""
            if cls._instance is None:
                cls._instance = cls()
            return cls._instance

    @staticmethod
    def fix_kind_mismatch(
        schema_oc: FlextLdifModelsDomainsEntries.SchemaObjectClass,
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
            sup_lower = str(first_sup).lower() if first_sup else ""
        schema_constants = FlextLdifUtilitiesObjectClass._SchemaConstants.get_instance()
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
        schema_oc: FlextLdifModelsDomainsEntries.SchemaObjectClass,
    ) -> None:
        """Fix AUXILIARY ObjectClass missing SUP (superior) attribute."""
        schema_constants = FlextLdifUtilitiesObjectClass._SchemaConstants.get_instance()
        if schema_oc.kind == schema_constants.auxiliary and (not schema_oc.sup):
            object.__setattr__(schema_oc, "sup", "top")
