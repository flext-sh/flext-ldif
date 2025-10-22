"""Fixture helper utilities for LDAP schema and entry manipulation.

Provides utilities for extracting, parsing, and validating LDIF fixture data.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import re


def extract_attributes(ldif_content: str) -> list[str]:
    """Extract attribute type definitions from LDIF content.

    Args:
        ldif_content: LDIF formatted string containing schema definitions

    Returns:
        List of attribute type definition strings

    """
    pattern = r"attributetypes:\s*\([^\)]+\)"
    matches = re.findall(pattern, ldif_content, re.MULTILINE | re.DOTALL)
    return [match.replace("attributetypes: ", "").strip() for match in matches]


def extract_objectclasses(ldif_content: str) -> list[str]:
    """Extract objectClass definitions from LDIF content.

    Args:
        ldif_content: LDIF formatted string containing schema definitions

    Returns:
        List of objectClass definition strings

    """
    pattern = r"objectclasses:\s*\([^\)]+\)"
    matches = re.findall(pattern, ldif_content, re.MULTILINE | re.DOTALL)
    return [match.replace("objectclasses: ", "").strip() for match in matches]


def extract_entries(ldif_content: str) -> list[dict[str, object]]:
    """Extract LDAP entries from LDIF content.

    Args:
        ldif_content: LDIF formatted string containing directory entries

    Returns:
        List of parsed LDAP entries as dictionaries

    """
    entries: list[dict[str, object]] = []
    current_entry: dict[str, object] = {}
    lines = ldif_content.split("\n")

    i = 0
    while i < len(lines):
        line = lines[i].rstrip()

        # Skip comments and empty lines
        if not line or line.startswith("#"):
            i += 1
            continue

        # Handle line continuation (leading space)
        while i + 1 < len(lines) and lines[i + 1].startswith(" "):
            i += 1
            line += lines[i].lstrip()

        # DN line starts new entry
        if line.lower().startswith("dn:"):
            if current_entry:
                entries.append(current_entry)
            current_entry = {"dn": line[3:].strip()}

        # Attribute line
        elif ":" in line and current_entry:
            parts = line.split(":", 1)
            if len(parts) == 2:
                attr_name = parts[0].strip().lower()
                attr_value = parts[1].strip()

                if attr_name in current_entry:
                    # Multi-valued attribute
                    if not isinstance(current_entry[attr_name], list):
                        current_entry[attr_name] = [current_entry[attr_name]]
                    current_entry[attr_name].append(attr_value)
                else:
                    current_entry[attr_name] = attr_value

        i += 1

    if current_entry:
        entries.append(current_entry)

    return entries


def extract_oid(definition: str) -> str | None:
    """Extract OID from attribute or objectClass definition.

    Args:
        definition: Attribute or objectClass definition string

    Returns:
        OID string or None if not found

    """
    # Match pattern like "( 2.5.4.3 NAME ..."
    match = re.search(r"\(\s*([0-9\.]+)\s", definition)
    return match.group(1) if match else None


def extract_name(definition: str) -> str | None:
    """Extract NAME from attribute or objectClass definition.

    Args:
        definition: Attribute or objectClass definition string

    Returns:
        NAME value or None if not found

    """
    # Match NAME 'name' or NAME ( 'name1' 'name2' )
    match = re.search(r"NAME\s+(?:\(?\s*)'([^']+)'", definition)
    return match.group(1) if match else None


def extract_syntax(definition: str) -> str | None:
    """Extract SYNTAX from attribute definition.

    Args:
        definition: Attribute definition string

    Returns:
        SYNTAX OID or None if not found

    """
    match = re.search(r"SYNTAX\s+([0-9\.]+)", definition)
    return match.group(1) if match else None


def extract_equality_match(definition: str) -> str | None:
    """Extract EQUALITY matching rule from definition.

    Args:
        definition: Attribute definition string

    Returns:
        Equality matching rule or None if not found

    """
    match = re.search(r"EQUALITY\s+(\S+)", definition)
    return match.group(1) if match else None


def extract_sup(definition: str) -> str | None:
    """Extract SUP (superior) from objectClass definition.

    Args:
        definition: ObjectClass definition string

    Returns:
        Superior objectClass name or None if not found

    """
    match = re.search(r"SUP\s+(\S+)", definition)
    return match.group(1) if match else None


def extract_must_attributes(definition: str) -> list[str]:
    """Extract MUST attributes from objectClass definition.

    Args:
        definition: ObjectClass definition string

    Returns:
        List of mandatory attribute names

    """
    match = re.search(r"MUST\s+\(?\s*([^)]+?)\s*\)?(?:\s|$)", definition)
    if not match:
        return []

    attrs_str = match.group(1).strip()
    # Split by $ and clean up
    return [attr.strip() for attr in attrs_str.replace("$", ",").split(",")]


def extract_may_attributes(definition: str) -> list[str]:
    """Extract MAY attributes from objectClass definition.

    Args:
        definition: ObjectClass definition string

    Returns:
        List of optional attribute names

    """
    match = re.search(r"MAY\s+\(?\s*([^)]+?)\s*\)?(?:\s|$)", definition)
    if not match:
        return []

    attrs_str = match.group(1).strip()
    # Split by $ and clean up
    return [attr.strip() for attr in attrs_str.replace("$", ",").split(",")]


def is_structural(definition: str) -> bool:
    """Check if objectClass is STRUCTURAL.

    Args:
        definition: ObjectClass definition string

    Returns:
        True if STRUCTURAL, False otherwise

    """
    return bool(re.search(r"\bSTRUCTURAL\b", definition))


def is_auxiliary(definition: str) -> bool:
    """Check if objectClass is AUXILIARY.

    Args:
        definition: ObjectClass definition string

    Returns:
        True if AUXILIARY, False otherwise

    """
    return bool(re.search(r"\bAUXILIARY\b", definition))


def is_abstract(definition: str) -> bool:
    """Check if objectClass is ABSTRACT.

    Args:
        definition: ObjectClass definition string

    Returns:
        True if ABSTRACT, False otherwise

    """
    return bool(re.search(r"\bABSTRACT\b", definition))


def is_single_valued(definition: str) -> bool:
    """Check if attribute is SINGLE-VALUE.

    Args:
        definition: Attribute definition string

    Returns:
        True if SINGLE-VALUE, False otherwise

    """
    return bool(re.search(r"\bSINGLE-VALUE\b", definition))


def count_entries(ldif_content: str) -> int:
    """Count number of LDAP entries in LDIF content.

    Args:
        ldif_content: LDIF formatted string

    Returns:
        Number of LDAP entries

    """
    return len([
        line for line in ldif_content.split("\n") if line.lower().startswith("dn:")
    ])


__all__ = [
    "count_entries",
    "extract_attributes",
    "extract_entries",
    "extract_equality_match",
    "extract_may_attributes",
    "extract_must_attributes",
    "extract_name",
    "extract_objectclasses",
    "extract_oid",
    "extract_sup",
    "extract_syntax",
    "is_abstract",
    "is_auxiliary",
    "is_single_valued",
    "is_structural",
]
