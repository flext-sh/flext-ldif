"""Master class for all LDIF parsing utilities.

Python 3.13+ optimized implementation using:
- Nested classes for organized structure
- Protocol-based hooks for server customization
- Generator expressions for lazy evaluation

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

import structlog
from flext_core import FlextResult, r

from flext_ldif.models import m

logger = structlog.get_logger(__name__)


class FlextLdifUtilitiesParsers:
    """Master class for all LDIF parsing utilities.

    Contains nested classes for each parsing operation:
    - Entry: Parse individual entries
    - Attribute: Parse attribute definitions
    - ObjectClass: Parse objectClass definitions
    - Content: Parse multiple entries

    Example:
        >>> result = FlextLdifUtilitiesParsers.Entry.parse(
        ...     ldif_content, "oid", parse_attrs_hook
        ... )

    """

    # =========================================================================
    # ENTRY PARSER - Parse individual LDIF entries
    # =========================================================================

    class Entry:
        """Generalized entry parser with hook-based customization."""

        # ===== NESTED PROTOCOL DEFINITIONS =====

        class ParseCommentsHook(Protocol):
            """Protocol for parsing comments and metadata."""

            def __call__(
                self,
                lines: list[str],
            ) -> dict[str, list[str]]: ...

        class ParseAttributesHook(Protocol):
            """Protocol for parsing attributes."""

            def __call__(
                self,
                lines: list[str],
            ) -> dict[str, list[str]]: ...

        class ParseValueHook(Protocol):
            """Protocol for parsing attribute values."""

            def __call__(self, attr_name: str, value: str) -> str: ...

        class TransformEntryHook(Protocol):
            """Protocol for entry transformation after parse."""

            def __call__(
                self,
                entry: m.Ldif.Entry,
            ) -> m.Ldif.Entry: ...

        class ParseDnHook(Protocol):
            """Protocol for parsing DN line."""

            def __call__(self, line: str) -> str | None: ...

        # ===== NESTED STATISTICS DATACLASS =====

        @dataclass(slots=True)
        class Stats:
            """Statistics for entry parsing."""

            total_entries: int = 0
            successful: int = 0
            failed: int = 0
            total_attributes: int = 0
            base64_values: int = 0

        # ===== STATIC METHODS =====

        @staticmethod
        def parse(
            ldif_content: str,
            server_type: str,
            parse_attributes_hook: ParseAttributesHook,
            *,
            parse_dn_hook: ParseDnHook | None = None,
            transform_entry_hook: TransformEntryHook | None = None,
            parse_comments_hook: ParseCommentsHook | None = None,
        ) -> r[m.Ldif.Entry]:
            """Parse LDIF entry from content using hooks.

            Args:
                ldif_content: LDIF content to parse
                server_type: Server type identifier
                parse_attributes_hook: Core attributes parsing
                parse_dn_hook: Optional DN parsing
                transform_entry_hook: Optional entry transformation
                parse_comments_hook: Optional comments parsing

            Returns:
                FlextResult with parsed Entry

            """
            try:
                lines = ldif_content.strip().split("\n")
                dn: str | None = None
                attributes: dict[str, list[str]] = {}

                # Parse DN
                for line in lines:
                    if line.lower().startswith("dn:"):
                        if parse_dn_hook:
                            dn = parse_dn_hook(line)
                        else:
                            dn = line.split(":", 1)[1].strip()
                        break

                if dn is None:
                    return r[m.Ldif.Entry].fail("No DN found in LDIF content")

                # Parse attributes
                attributes = parse_attributes_hook(lines)

                # Parse comments if hook provided
                if parse_comments_hook:
                    comments = parse_comments_hook(lines)
                    attributes.update(comments)

                # Create entry
                # Entry field validators will coerce str -> DistinguishedName and dict -> LdifAttributes
                # Convert types explicitly for mypy
                dn_obj = (
                    dn
                    if isinstance(dn, m.DistinguishedName)
                    else m.DistinguishedName(value=dn)
                )
                attrs_obj = (
                    attributes
                    if isinstance(attributes, m.LdifAttributes)
                    else m.LdifAttributes(attributes=attributes)
                )
                entry = m.Ldif.Entry(dn=dn_obj, attributes=attrs_obj)

                # Transform if hook provided
                if transform_entry_hook:
                    entry = transform_entry_hook(entry)

                return r[m.Ldif.Entry].ok(entry)

            except Exception as e:
                logger.exception(
                    "Failed to parse entry",
                    server_type=server_type,
                )
                return r[m.Ldif.Entry].fail(f"Failed to parse entry: {e}")

    # =========================================================================
    # ATTRIBUTE PARSER - Parse attribute type definitions
    # =========================================================================

    class Attribute:
        """Generalized attribute definition parser."""

        # ===== NESTED PROTOCOL DEFINITIONS =====

        class ParsePartsHook(Protocol):
            """Protocol for parsing attribute definition parts."""

            def __call__(
                self,
                definition: str,
            ) -> dict[str, str | bool | None]: ...

        class TransformHook(Protocol):
            """Protocol for attribute transformation."""

            def __call__(
                self,
                attribute: m.Ldif.SchemaAttribute,
            ) -> m.Ldif.SchemaAttribute: ...

        class ParseOidHook(Protocol):
            """Protocol for OID parsing."""

            def __call__(self, definition: str) -> str | None: ...

        # ===== STATIC METHODS =====

        @staticmethod
        def parse(
            definition: str,
            server_type: str,
            parse_parts_hook: ParsePartsHook,
            *,
            transform_hook: TransformHook | None = None,
            parse_oid_hook: ParseOidHook | None = None,
        ) -> FlextResult[m.Ldif.SchemaAttribute]:
            """Parse attribute definition using hooks.

            Args:
                definition: Attribute definition string
                server_type: Server type identifier
                parse_parts_hook: Core parts parsing
                transform_hook: Optional attribute transformation
                parse_oid_hook: Optional OID parsing

            Returns:
                FlextResult with SchemaAttribute

            """
            try:
                # Parse parts using hook
                parts = parse_parts_hook(definition)

                # Parse OID if hook provided
                oid = parts.get("oid", "")
                if parse_oid_hook:
                    parsed_oid = parse_oid_hook(definition)
                    if parsed_oid:
                        oid = parsed_oid

                # Create attribute
                attribute = m.Ldif.SchemaAttribute(
                    oid=str(oid) if oid else "",
                    name=str(parts.get("name", oid or "")),
                    desc=str(parts.get("desc")) if parts.get("desc") else None,
                    syntax=str(parts.get("syntax")) if parts.get("syntax") else None,
                    equality=(
                        str(parts.get("equality")) if parts.get("equality") else None
                    ),
                    ordering=(
                        str(parts.get("ordering")) if parts.get("ordering") else None
                    ),
                    substr=str(parts.get("substr")) if parts.get("substr") else None,
                    single_value=bool(parts.get("single_value", False)),
                    no_user_modification=bool(parts.get("no_user_modification", False)),
                    sup=str(parts.get("sup")) if parts.get("sup") else None,
                    usage=str(parts.get("usage")) if parts.get("usage") else None,
                )

                # Transform if hook provided
                if transform_hook:
                    attribute = transform_hook(attribute)

                return FlextResult[m.Ldif.SchemaAttribute].ok(attribute)

            except Exception as e:
                logger.exception(
                    "Failed to parse attribute",
                    server_type=server_type,
                )
                return FlextResult.fail(f"Failed to parse attribute: {e}")

    # =========================================================================
    # OBJECTCLASS PARSER - Parse objectClass definitions
    # =========================================================================

    class ObjectClass:
        """Generalized objectClass definition parser."""

        # ===== NESTED PROTOCOL DEFINITIONS =====

        class ParsePartsHook(Protocol):
            """Protocol for parsing objectClass definition parts."""

            def __call__(
                self,
                definition: str,
            ) -> dict[str, str | list[str] | None]: ...

        class TransformHook(Protocol):
            """Protocol for objectClass transformation."""

            def __call__(
                self,
                objectclass: m.Ldif.SchemaObjectClass,
            ) -> m.Ldif.SchemaObjectClass: ...

        # ===== STATIC METHODS =====

        @staticmethod
        def parse(
            definition: str,
            server_type: str,
            parse_parts_hook: ParsePartsHook,
            *,
            transform_hook: TransformHook | None = None,
        ) -> FlextResult[m.Ldif.SchemaObjectClass]:
            """Parse objectClass definition using hooks.

            Args:
                definition: ObjectClass definition string
                server_type: Server type identifier
                parse_parts_hook: Core parts parsing
                transform_hook: Optional objectClass transformation

            Returns:
                FlextResult with SchemaObjectClass

            """
            try:
                # Parse parts using hook
                parts = parse_parts_hook(definition)

                # Extract lists
                must = parts.get("must")
                if must is not None and not isinstance(must, list):
                    must = [str(must)]

                may = parts.get("may")
                if may is not None and not isinstance(may, list):
                    may = [str(may)]

                # Create objectClass
                objectclass = m.Ldif.SchemaObjectClass(
                    oid=str(parts.get("oid", "")),
                    name=str(parts.get("name", parts.get("oid", ""))),
                    desc=str(parts.get("desc")) if parts.get("desc") else None,
                    sup=str(parts.get("sup")) if parts.get("sup") else None,
                    kind=str(parts.get("kind", "STRUCTURAL")),
                    must=must,
                    may=may,
                )

                # Transform if hook provided
                if transform_hook:
                    objectclass = transform_hook(objectclass)

                return FlextResult[m.Ldif.SchemaObjectClass].ok(objectclass)

            except Exception as e:
                logger.exception(
                    "Failed to parse objectClass",
                    server_type=server_type,
                )
                return FlextResult.fail(f"Failed to parse objectClass: {e}")

    # =========================================================================
    # CONTENT PARSER - Parse multiple entries
    # =========================================================================

    class Content:
        """Generalized content parser for multiple entries."""

        # ===== NESTED PROTOCOL DEFINITIONS =====

        class ParseEntryHook(Protocol):
            """Protocol for parsing individual entries."""

            def __call__(self, entry_content: str) -> r[m.Ldif.Entry]: ...

        class ParseHeaderHook(Protocol):
            """Protocol for parsing LDIF header."""

            def __call__(self, header: str) -> dict[str, str]: ...

        # ===== NESTED STATISTICS DATACLASS =====

        @dataclass(slots=True)
        class Stats:
            """Statistics for content parsing."""

            total_entries: int = 0
            successful: int = 0
            failed: int = 0

        # ===== STATIC METHODS =====

        @staticmethod
        def parse(
            ldif_content: str,
            server_type: str,
            parse_entry_hook: ParseEntryHook,
            *,
            _parse_header_hook: ParseHeaderHook | None = None,
        ) -> r[list[m.Ldif.Entry]]:
            """Parse multiple entries from LDIF content.

            Args:
                ldif_content: LDIF content to parse
                server_type: Server type identifier
                parse_entry_hook: Hook for parsing individual entries
                _parse_header_hook: Optional header parsing (reserved for future use)

            Returns:
                FlextResult with list of parsed entries

            """
            try:
                entries: list[m.Ldif.Entry] = []
                stats = FlextLdifUtilitiesParsers.Content.Stats()

                # Split content by empty lines
                raw_entries = ldif_content.strip().split("\n\n")
                stats.total_entries = len(raw_entries)

                for raw_entry in raw_entries:
                    if not raw_entry.strip():
                        continue

                    processed_entry = ""
                    # Handle version line (global header or per-entry if malformed)
                    # Business Rule: RFC 2849 specifies version header at start of file
                    # If split logic groups it with first entry, strip it but keep entry content
                    lines = raw_entry.strip().split("\n")
                    if lines and lines[0].lower().startswith("version:"):
                        lines = lines[1:]
                        if not lines:
                            # Block was only version header
                            continue
                        processed_entry = "\n".join(lines)
                    else:
                        processed_entry = raw_entry.strip()

                    result = parse_entry_hook(processed_entry)
                    if result.is_success:
                        stats.successful += 1
                        entries.append(result.unwrap())
                    else:
                        stats.failed += 1
                        logger.warning(
                            "Failed to parse entry",
                            error=str(result.error),
                            server_type=server_type,
                        )

                return r[list[m.Ldif.Entry]].ok(entries)

            except Exception as e:
                logger.exception(
                    "Failed to parse content",
                    server_type=server_type,
                )
                return r[list[m.Ldif.Entry]].fail(f"Failed to parse content: {e}")


__all__ = ["FlextLdifUtilitiesParsers"]
