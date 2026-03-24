"""Extracted nested class from FlextLdifUtilities."""

from __future__ import annotations

import struct
from collections.abc import Callable, MutableSequence

from flext_core import FlextLogger, r

from flext_ldif import FlextLdifModelsDomains, FlextLdifUtilitiesSchema, c, m, t

logger = FlextLogger(__name__)
_ParsedObjectClass = FlextLdifModelsDomains.ParsedObjectClass


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
    def align_kind_with_superior(
        schema_oc: FlextLdifModelsDomains.SchemaObjectClass,
        superior_kind: str | None,
    ) -> None:
        """Align ObjectClass kind with its superior class kind."""
        if (
            schema_oc.sup
            and schema_oc.kind
            and superior_kind
            and (schema_oc.kind != superior_kind)
        ):
            setattr(schema_oc, "kind", superior_kind)

    @staticmethod
    def ensure_sup_for_auxiliary(
        schema_oc: FlextLdifModelsDomains.SchemaObjectClass,
        default_sup: str = "top",
    ) -> None:
        """Ensure AUXILIARY ObjectClass has SUP attribute."""
        schema_constants = FlextLdifUtilitiesObjectClass._SchemaConstants.get_instance()
        if schema_oc.kind == schema_constants.auxiliary and (not schema_oc.sup):
            setattr(schema_oc, "sup", default_sup)

    @staticmethod
    def fix_kind_mismatch(
        schema_oc: FlextLdifModelsDomains.SchemaObjectClass,
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
        elif sup_value is not None:
            first_sup = sup_value[0] if sup_value else ""
            sup_lower = str(first_sup).lower() if first_sup else ""
        else:
            sup_lower = ""
        schema_constants = FlextLdifUtilitiesObjectClass._SchemaConstants.get_instance()
        if (
            sup_lower in structural_superiors
            and schema_oc.kind == schema_constants.auxiliary
        ):
            setattr(schema_oc, "kind", schema_constants.structural)
        elif (
            sup_lower in auxiliary_superiors
            and schema_oc.kind == schema_constants.structural
        ):
            setattr(schema_oc, "kind", schema_constants.auxiliary)

    @staticmethod
    def fix_missing_sup(schema_oc: FlextLdifModelsDomains.SchemaObjectClass) -> None:
        """Fix AUXILIARY ObjectClass missing SUP (superior) attribute."""
        schema_constants = FlextLdifUtilitiesObjectClass._SchemaConstants.get_instance()
        if schema_oc.kind == schema_constants.auxiliary and (not schema_oc.sup):
            setattr(schema_oc, "sup", "top")

    @staticmethod
    def resolve_objectclass(
        definition: str,
        server_type: str | None = None,
        parse_parts_hook: Callable[[str], t.MutableContainerMapping] | None = None,
    ) -> r[m.Ldif.SchemaObjectClass]:
        """Parse RFC 4512 objectClass definition into SchemaObjectClass model."""
        try:
            parsed_dict: t.MutableContainerMapping = (
                FlextLdifUtilitiesSchema.parse_objectclass(definition)
            )
            if parse_parts_hook is not None:
                parsed_dict = parse_parts_hook(definition)
            oid_raw = parsed_dict.get("oid")
            if not isinstance(oid_raw, str):
                return r[m.Ldif.SchemaObjectClass].fail(
                    "Failed to parse objectClass definition: missing oid",
                )
            name_raw = parsed_dict.get("name")
            name_value = name_raw if isinstance(name_raw, str) else ""
            desc_raw = parsed_dict.get("desc")
            desc_value = desc_raw if isinstance(desc_raw, str) else None
            sup_raw = parsed_dict.get("sup")
            sup_value: str | MutableSequence[str] | None
            if isinstance(sup_raw, str):
                sup_value = sup_raw
            elif isinstance(sup_raw, list):
                sup_value = [str(item) for item in sup_raw]
            else:
                sup_value = None
            kind_raw = parsed_dict.get("kind")
            kind_value = kind_raw if isinstance(kind_raw, str) else ""
            must_raw = parsed_dict.get("must")
            must_value: MutableSequence[str] = []
            if isinstance(must_raw, list):
                must_value = [str(item) for item in must_raw]
            may_raw = parsed_dict.get("may")
            may_value: MutableSequence[str] = []
            if isinstance(may_raw, list):
                may_value = [str(item) for item in may_raw]
            schema_oc = m.Ldif.SchemaObjectClass(
                oid=oid_raw,
                name=name_value,
                desc=desc_value,
                sup=sup_value,
                kind=kind_value,
                must=must_value,
                may=may_value,
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
                f"Failed to parse objectClass definition: {e}",
            )
