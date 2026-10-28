"""LDIF entry RFC structural validation utilities.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import MutableSequence, Sequence

from flext_ldif import c, p


class FlextLdifUtilitiesEntryValidation:
    """Validate entry DN, attributes, changetype, and naming per RFC 2849/4512."""

    @staticmethod
    def validate_dn_format(dn_value: str) -> MutableSequence[str]:
        """Validate DN format per RFC 4514 section 2.3, 2.4.

        Args:
            dn_value: DN string to validate

        Returns:
            List of validation violation messages (empty if valid)

        """
        if not dn_value or not dn_value.strip():
            return ["RFC 2849 § 2: DN is required (empty or whitespace DN)"]
        if not FlextLdifUtilitiesEntryValidation.dn_components(dn_value):
            return ["RFC 4514 § 2.4: DN is empty (no RDN components)"]
        return FlextLdifUtilitiesEntryValidation.dn_component_violations(dn_value)

    @staticmethod
    def dn_components(dn_value: str) -> Sequence[str]:
        r"""Split a DN into its RDN components per RFC 4514 section 2.

        A backslash escapes the next character (``\,`` is not a separator);
        a lone trailing backslash stays literal.

        Returns:
            The stripped, non-empty RDN components in order.

        """
        components: list[str] = []
        current = ""
        chars = iter(dn_value)
        for char in chars:
            if char == "\\":
                current += "\\" + next(chars, "")
            elif char == "," and current.strip():
                components.append(current.strip())
                current = ""
            elif char != ",":
                current += char
        if current.strip():
            components.append(current.strip())
        return tuple(components)

    @staticmethod
    def naming_attribute(dn_value: str) -> str | None:
        """Return the lower-cased attribute naming the DN's first RDN.

        Returns:
            The naming attribute, or ``None`` when the first RDN has none.

        """
        components = FlextLdifUtilitiesEntryValidation.dn_components(dn_value)
        if not components or "=" not in components[0]:
            return None
        return components[0].split("=", maxsplit=1)[0].strip().lower()

    @staticmethod
    def dn_component_violations(dn_value: str) -> MutableSequence[str]:
        """Return one RFC 4514 § 2.3 violation per malformed RDN component.

        Returns:
            The violation descriptions, empty when every component is valid.

        """
        return [
            f"RFC 4514 § 2.3: invalid DN component {component!r} in DN {dn_value!r}"
            for component in FlextLdifUtilitiesEntryValidation.dn_components(dn_value)
            if not c.Ldif.DN_COMPONENT_RE.match(component)
        ]

    @staticmethod
    def validate_attributes_required(
        entry: p.Ldif.Entry,
    ) -> MutableSequence[str]:
        """Validate that entry has at least one attribute per RFC 2849 section 2.

        Note: entry.attributes may be None when using model_construct (bypasses
        validation).

        Returns:
            The resulting ``MutableSequence[str]``.

        """
        violations: MutableSequence[str] = []
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
        entry: p.Ldif.Entry,
    ) -> MutableSequence[str]:
        """Validate changetype field per RFC 2849 section 5.7.

        Returns:
            The resulting ``MutableSequence[str]``.

        """
        violations: MutableSequence[str] = []
        if not entry.changetype:
            return violations
        valid_changetypes = {"add", "delete", "modify", "moddn", "modrdn"}
        if entry.changetype.lower() not in valid_changetypes:
            violations.append(
                f"RFC 2849 § 5.7: changetype '{entry.changetype}' invalid",
            )
        return violations

    @staticmethod
    def _attribute_required(
        entry: p.Ldif.Entry,
        attribute_name: str,
        violation_message: str,
    ) -> MutableSequence[str]:
        """Require one case-insensitive attribute on a changeless entry.

        Note: entry.attributes may be None when using model_construct (bypasses
        validation).

        Args:
            entry: Entry subject carrying parsed attributes.
            attribute_name: Required attribute name in lowercase.
            violation_message: RFC citation emitted when the attribute is absent.

        Returns:
            The resulting ``MutableSequence[str]``.

        """
        violations: MutableSequence[str] = []
        if entry.changetype:
            return violations
        if entry.attributes is None or (not entry.attributes):
            return violations
        if not any(
            attr_name.lower() == attribute_name
            for attr_name in entry.attributes.attributes
        ):
            violations.append(violation_message)
        return violations

    @staticmethod
    def validate_naming_attribute(
        entry: p.Ldif.Entry,
        dn_value: str,
    ) -> MutableSequence[str]:
        """Validate naming attribute presence per RFC 4512 section 2.3.

        Note: entry.attributes may be None when using model_construct (bypasses
        validation).

        Returns:
            The resulting ``MutableSequence[str]``.

        """
        naming_attr = FlextLdifUtilitiesEntryValidation.naming_attribute(dn_value)
        if naming_attr is None:
            return []
        return FlextLdifUtilitiesEntryValidation._attribute_required(
            entry,
            naming_attr,
            f"RFC 4512 § 2.3: Entry SHOULD have Naming attribute '{naming_attr}'",
        )

    @staticmethod
    def validate_objectclass(
        entry: p.Ldif.Entry,
        dn_value: str,
    ) -> MutableSequence[str]:
        """Validate objectClass presence per RFC 4512 section 2.4.1.

        Note: entry.attributes may be None when using model_construct (bypasses
        validation).

        Returns:
            The resulting ``MutableSequence[str]``.

        """
        dn_value_lower = dn_value.lower()
        is_schema_entry = any(
            dn_value_lower.startswith(marker) for marker in c.Ldif.SCHEMA_DN_MARKERS
        )
        if is_schema_entry:
            return []
        return FlextLdifUtilitiesEntryValidation._attribute_required(
            entry,
            c.Ldif.DictKeys.OBJECTCLASS.lower(),
            f"RFC 4512 § 2.4.1: Entry SHOULD have objectClass (DN: {dn_value})",
        )


__all__: list[str] = ["FlextLdifUtilitiesEntryValidation"]
