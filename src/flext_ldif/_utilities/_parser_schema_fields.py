"""RFC 4512 schema definition field extraction utilities.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_core import r

from flext_ldif import c, p, t


class FlextLdifParserSchemaFields:
    """Extract OIDs and optional fields from schema definition strings."""

    @staticmethod
    def extract_oid(definition: str) -> p.Result[str]:
        """Extract OID from schema definition string.

        Returns:
            The resulting ``p.Result[str]``.
        """
        if not definition:
            return r[str].fail("Empty definition: cannot extract OID")
        match = c.Ldif.SCHEMA_OID_CAPTURE_RE.match(definition.strip())
        if match:
            return r[str].ok(match.group(1))
        return r[str].fail(f"missing an OID in definition: {definition!r}")

    @staticmethod
    def extract_optional_field(
        definition: str,
        pattern: t.Ldif.RegexPattern | str,
        default: str | None = None,
    ) -> str | None:
        """Extract optional field via regex pattern.

        Returns:
            The resulting ``str | None``.
        """
        if not definition:
            return default
        compiled = (
            pattern if not isinstance(pattern, str) else c.Ldif.compile_pattern(pattern)
        )
        match = compiled.search(definition)
        return match.group(1) if match else default

    @staticmethod
    def extract_boolean_flag(
        definition: str,
        pattern: t.Ldif.RegexPattern | str,
    ) -> bool:
        """Check if boolean flag exists in definition.

        Returns:
            The resulting ``bool``.
        """
        if not definition:
            return False
        compiled = (
            pattern if not isinstance(pattern, str) else c.Ldif.compile_pattern(pattern)
        )
        return compiled.search(definition) is not None

    @staticmethod
    def extract_extensions(definition: str) -> t.MutableStrSequenceMapping:
        """Extract extension information from schema definition string.

        Returns:
            The resulting ``t.MutableStrSequenceMapping``.
        """
        if not definition:
            return {}
        extensions: t.MutableStrSequenceMapping = {}
        for match in c.Ldif.SCHEMA_X_EXTENSION_RE.finditer(definition):
            key = f"X-{match.group(1)}"
            value = match.group(2).strip()
            extensions[key] = [value]
        desc_match = c.Ldif.SCHEMA_DESC_FLEX_RE.search(definition)
        if desc_match:
            extensions["DESC"] = [desc_match.group(1)]
        ordering_match = c.Ldif.SCHEMA_ORDERING_TOKEN_RE.search(definition)
        if ordering_match:
            extensions["ORDERING"] = [ordering_match.group(1)]
        substr_match = c.Ldif.SCHEMA_SUBSTR_TOKEN_RE.search(definition)
        if substr_match:
            extensions["SUBSTR"] = [substr_match.group(1)]
        return extensions


__all__: list[str] = ["FlextLdifParserSchemaFields"]
