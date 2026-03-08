"""Extracted nested class from FlextLdifUtilities."""

from __future__ import annotations

import struct
from collections.abc import Callable, Mapping

from flext_core import FlextLogger, r

from flext_ldif import c, m, t
from flext_ldif._models.domain import FlextLdifModelsDomains
from flext_ldif._utilities.schema import FlextLdifUtilitiesSchema


class _SchemaConstants:
    """Schema constants container for type safety (single class, no loose helpers)."""

    _instance: _SchemaConstants | None = None
    auxiliary: str
    structural: str

    def __init__(self) -> None:
        """Initialize schema constants from SchemaKind enum."""
        super().__init__()
        self.auxiliary = c.Ldif.SchemaKind.AUXILIARY.value
        self.structural = c.Ldif.SchemaKind.STRUCTURAL.value

    @classmethod
    def get_instance(cls) -> _SchemaConstants:
        """Return cached schema constants instance (avoids repeated getattr)."""
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance


logger = FlextLogger(__name__)
_ParsedObjectClass = FlextLdifModelsDomains.ParsedObjectClass


class FlextLdifUtilitiesObjectClass:
    """RFC 4512 ObjectClass Validation and Correction Utilities."""

    @staticmethod
    def align_kind_with_superior(
        schema_oc: FlextLdifModelsDomains.SchemaObjectClass, superior_kind: str | None
    ) -> None:
        """Align ObjectClass kind with its superior class kind."""
        if (
            schema_oc.sup
            and schema_oc.kind
            and superior_kind
            and (schema_oc.kind != superior_kind)
        ):
            schema_oc.kind = superior_kind

    @staticmethod
    def ensure_sup_for_auxiliary(
        schema_oc: FlextLdifModelsDomains.SchemaObjectClass, default_sup: str = "top"
    ) -> None:
        """Ensure AUXILIARY ObjectClass has SUP attribute."""
        schema_constants = _SchemaConstants.get_instance()
        if schema_oc.kind == schema_constants.auxiliary and (not schema_oc.sup):
            schema_oc.sup = default_sup

    @staticmethod
    def fix_kind_mismatch(
        schema_oc: FlextLdifModelsDomains.SchemaObjectClass, _server_type: str = "oid"
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
        if isinstance(sup_value, list):
            first_sup = sup_value[0] if sup_value else ""
            sup_lower = str(first_sup).lower() if first_sup else ""
        else:
            sup_lower = sup_value.lower() if sup_value else ""
        schema_constants = _SchemaConstants.get_instance()
        if (
            sup_lower in structural_superiors
            and schema_oc.kind == schema_constants.auxiliary
        ):
            schema_oc.kind = schema_constants.structural
        elif (
            sup_lower in auxiliary_superiors
            and schema_oc.kind == schema_constants.structural
        ):
            schema_oc.kind = schema_constants.auxiliary

    @staticmethod
    def fix_missing_sup(schema_oc: FlextLdifModelsDomains.SchemaObjectClass) -> None:
        """Fix AUXILIARY ObjectClass missing SUP (superior) attribute."""
        schema_constants = _SchemaConstants.get_instance()
        if schema_oc.kind == schema_constants.auxiliary and (not schema_oc.sup):
            schema_oc.sup = "top"

    @staticmethod
    def parse(
        definition: str,
        server_type: str | None = None,
        parse_parts_hook: Callable[[str], Mapping[str, t.ContainerValue]] | None = None,
    ) -> r[m.Ldif.SchemaObjectClass]:
        """Parse RFC 4512 objectClass definition into SchemaObjectClass model."""
        try:
            parsed_dict: Mapping[str, t.ContainerValue] = (
                FlextLdifUtilitiesSchema.parse_objectclass(definition)
            )
            if parse_parts_hook is not None:
                parsed_dict = parse_parts_hook(definition)
            parsed_model = _ParsedObjectClass.model_validate(parsed_dict)
            schema_oc = m.Ldif.SchemaObjectClass(
                oid=parsed_model.oid,
                name=parsed_model.name,
                desc=parsed_model.desc,
                sup=parsed_model.sup,
                kind=parsed_model.kind,
                must=parsed_model.must,
                may=parsed_model.may,
            )
            if server_type:
                FlextLdifUtilitiesObjectClass.fix_missing_sup(schema_oc)
            return r[m.Ldif.SchemaObjectClass].ok(schema_oc)
        except (
            ValueError,
            KeyError,
            AttributeError,
            UnicodeDecodeError,
            struct.error,
        ) as e:
            return r[m.Ldif.SchemaObjectClass].fail(
                f"Failed to parse objectClass definition: {e}"
            )
