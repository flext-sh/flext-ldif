"""LDIF schema definition part-assembly utilities.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from flext_ldif import c, t

if TYPE_CHECKING:
    from flext_ldif import FlextLdifModels


class FlextLdifWriterSchemaParts:
    """Assemble schema definition part lists and finalize LDIF text."""

    @staticmethod
    def add_attribute_flags(
        attr_data: FlextLdifModels.Ldif.SchemaAttribute,
        parts: t.MutableSequenceOf[str],
    ) -> None:
        """Add flags to attribute parts list."""
        if attr_data.single_value:
            parts.append("SINGLE-VALUE")
        collective = (
            attr_data.metadata.extensions.get(c.Ldif.COLLECTIVE)
            if attr_data.metadata is not None
            else False
        )
        if collective is True:
            parts.append("COLLECTIVE")
        if attr_data.no_user_modification:
            parts.append("NO-USER-MODIFICATION")

    @staticmethod
    def add_attribute_matching_rules(
        attr_data: FlextLdifModels.Ldif.SchemaAttribute,
        parts: t.MutableSequenceOf[str],
    ) -> None:
        """Add matching rules to attribute parts list."""
        if attr_data.equality:
            parts.append(f"EQUALITY {attr_data.equality}")
        if attr_data.ordering:
            parts.append(f"ORDERING {attr_data.ordering}")
        if attr_data.substr:
            parts.append(f"SUBSTR {attr_data.substr}")

    @staticmethod
    def add_attribute_syntax(
        attr_data: FlextLdifModels.Ldif.SchemaAttribute,
        parts: t.MutableSequenceOf[str],
    ) -> None:
        """Add syntax and length to attribute parts list."""
        if attr_data.syntax:
            syntax_str = attr_data.syntax
            if attr_data.length is not None:
                syntax_str += f"{{{attr_data.length}}}"
            parts.append(f"SYNTAX {syntax_str}")

    @staticmethod
    def finalize_ldif_text(ldif_lines: t.MutableSequenceOf[str]) -> str:
        """Join LDIF lines and ensure proper trailing newline.

        Returns:
            The resulting ``str``.
        """
        ldif_text = "\n".join(ldif_lines)
        if ldif_text and (not ldif_text.endswith("\n")):
            ldif_text += "\n"
        return ldif_text


__all__: list[str] = ["FlextLdifWriterSchemaParts"]
