"""LDIF entry RFC structural validation utilities.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_ldif import c, p, t


class FlextLdifEntryValidation:
    """Validate entry DN, attributes, changetype, and naming per RFC 2849/4512."""

    @staticmethod
    def validate_dn_format(dn_value: str) -> t.MutableSequenceOf[str]:
        """Validate DN format per RFC 4514 section 2.3, 2.4.

        Args:
            dn_value: DN string to validate

        Returns:
            List of validation violation messages (empty if valid)

        """
        violations: t.MutableSequenceOf[str] = []
        if not dn_value or not dn_value.strip():
            violations.append("RFC 2849 § 2: DN is required (empty or whitespace DN)")
            return violations
        components = [comp.strip() for comp in dn_value.split(",") if comp.strip()]
        if not components:
            violations.append("RFC 4514 § 2.4: DN is empty (no RDN components)")
            return violations
        for idx, comp in enumerate(components):
            if not c.Ldif.DN_COMPONENT_RE.match(comp):
                violations.append(
                    f"RFC 4514 § 2.3: Component {idx} '{comp}' invalid format",
                )
        return violations

    @staticmethod
    def validate_attributes_required(
        entry: p.Ldif.EntryValidationSubject,
    ) -> t.MutableSequenceOf[str]:
        """Validate that entry has at least one attribute per RFC 2849 section 2.

        Note: entry.attributes may be None when using model_construct (bypasses
        validation).

        Returns:
            The resulting ``t.MutableSequenceOf[str]``.
        """
        violations: t.MutableSequenceOf[str] = []
        if entry.changetype in {"delete", "moddn", "modrdn"}:
            return violations
        change_operations = getattr(entry, "change_operations", [])
        if entry.changetype == "modify" and change_operations:
            return violations
        if entry.attributes is None:
            violations.append(
                "RFC 2849 § 2: Entry must have at least one attribute (missing)",
            )
            return violations
        if not entry.attributes:
            violations.append(
                "RFC 2849 § 2: Entry must have at least one attribute (empty)",
            )
        return violations

    @staticmethod
    def validate_changetype(
        entry: p.Ldif.EntryValidationSubject,
    ) -> t.MutableSequenceOf[str]:
        """Validate changetype field per RFC 2849 section 5.7.

        Returns:
            The resulting ``t.MutableSequenceOf[str]``.
        """
        violations: t.MutableSequenceOf[str] = []
        if not entry.changetype:
            return violations
        valid_changetypes = {"add", "delete", "modify", "moddn", "modrdn"}
        if entry.changetype.lower() not in valid_changetypes:
            violations.append(
                f"RFC 2849 § 5.7: changetype '{entry.changetype}' invalid",
            )
        return violations

    @staticmethod
    def validate_naming_attribute(
        entry: p.Ldif.EntryValidationSubject,
        dn_value: str,
    ) -> t.MutableSequenceOf[str]:
        """Validate naming attribute presence per RFC 4512 section 2.3.

        Note: entry.attributes may be None when using model_construct (bypasses
        validation).

        Returns:
            The resulting ``t.MutableSequenceOf[str]``.
        """
        violations: t.MutableSequenceOf[str] = []
        if entry.changetype:
            return violations
        if not dn_value or entry.attributes is None or (not entry.attributes):
            return violations
        first_rdn = (
            dn_value.split(",", maxsplit=1)[0].strip()
            if "," in dn_value
            else dn_value.strip()
        )
        if "=" not in first_rdn:
            return violations
        naming_attr = first_rdn.split("=")[0].strip().lower()
        has_naming_attr = any(
            attr_name.lower() == naming_attr
            for attr_name in entry.attributes.attributes
        )
        if not has_naming_attr:
            violations.append(
                f"RFC 4512 § 2.3: Entry SHOULD have Naming attribute '{naming_attr}'",
            )
        return violations

    @staticmethod
    def validate_objectclass(
        entry: p.Ldif.EntryValidationSubject,
        dn_value: str,
    ) -> t.MutableSequenceOf[str]:
        """Validate objectClass presence per RFC 4512 section 2.4.1.

        Note: entry.attributes may be None when using model_construct (bypasses
        validation).

        Returns:
            The resulting ``t.MutableSequenceOf[str]``.
        """
        violations: t.MutableSequenceOf[str] = []
        if entry.changetype:
            return violations
        dn_value_lower = dn_value.lower()
        is_schema_entry = any(
            dn_value_lower.startswith(marker) for marker in c.Ldif.SCHEMA_DN_MARKERS
        )
        if entry.attributes is None or is_schema_entry or (not entry.attributes):
            return violations
        has_objectclass = any(
            attr_name.lower() == c.Ldif.DictKeys.OBJECTCLASS.lower()
            for attr_name in entry.attributes.attributes
        )
        if not has_objectclass:
            violations.append(
                f"RFC 4512 § 2.4.1: Entry SHOULD have objectClass (DN: {dn_value})",
            )
        return violations


__all__: list[str] = ["FlextLdifEntryValidation"]
