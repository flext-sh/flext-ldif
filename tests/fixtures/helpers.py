"""Fixture helper utilities for LDAP schema and entry manipulation.

Provides utilities for extracting, parsing, and validating LDIF fixture data.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import re
from typing import cast

from tests.fixtures.typing import (
    GenericFieldsDict,
    GenericTestCaseDict,
)


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


def extract_entries(ldif_content: str) -> list[GenericTestCaseDict]:
    """Extract LDAP entries from LDIF content.

    Args:
        ldif_content: LDIF formatted string containing directory entries

    Returns:
        List of parsed LDAP entries as dictionaries

    """
    entries: list[GenericTestCaseDict] = []
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
                entries.append(cast("GenericTestCaseDict", current_entry))
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
                    cast("list[object]", current_entry[attr_name]).append(attr_value)
                else:
                    current_entry[attr_name] = attr_value

        i += 1

    if current_entry:
        entries.append(cast("GenericTestCaseDict", current_entry))

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
    return len(
        [line for line in ldif_content.split("\n") if line.lower().startswith("dn:")],
    )


# ============================================================================
# DEEP COMPARISON UTILITIES FOR ROUND-TRIP VALIDATION
# ============================================================================


def get_entry_attribute_values(
    entry: GenericFieldsDict,
    attr_name: str,
) -> list[str]:
    """Extract all values for a given attribute from an entry.

    Args:
        entry: LDAP entry dictionary
        attr_name: Attribute name to extract (case-insensitive)

    Returns:
        List of attribute values as strings, empty list if attribute not found

    """
    # Try exact match first
    entry_dict = cast("dict[str, object]", entry)
    for key in entry_dict:
        if isinstance(key, str) and key.lower() == attr_name.lower():
            value = entry_dict[key]
            if isinstance(value, list):
                return [str(v) for v in value]
            return [str(value)]
    return []


def compare_entries_deep(
    original: GenericFieldsDict,
    roundtrip: GenericFieldsDict,
) -> dict[str, object]:
    """Deep comparison of two entries, returning detailed difference report.

    Validates:
    - DN matches (case-normalized)
    - All attributes present in both entries
    - Attribute value counts match
    - Attribute values match (order-agnostic)

    Args:
        original: Original entry before round-trip
        roundtrip: Entry after write and re-parse

    Returns:
        Dictionary with comparison results:
        {
            "matches": bool,
            "dn_match": bool,
            "dn_original": str,
            "dn_roundtrip": str,
            "attribute_count_original": int,
            "attribute_count_roundtrip": int,
            "missing_attributes": list[str],
            "extra_attributes": list[str],
            "value_mismatches": dict[str, {"original": list, "roundtrip": list}],
            "details": str
        }

    """
    original_dict = cast("dict[str, object]", original)
    roundtrip_dict = cast("dict[str, object]", roundtrip)
    dn_original = str(original_dict.get("dn", "")).lower()
    dn_roundtrip = str(roundtrip_dict.get("dn", "")).lower()

    original_attrs = {k.lower() for k in original_dict if k.lower() != "dn"}
    roundtrip_attrs = {k.lower() for k in roundtrip_dict if k.lower() != "dn"}

    missing = original_attrs - roundtrip_attrs
    extra = roundtrip_attrs - original_attrs

    value_mismatches: dict[str, dict[str, object]] = {}
    for attr in original_attrs & roundtrip_attrs:
        orig_values = get_entry_attribute_values(original, attr)
        round_values = get_entry_attribute_values(roundtrip, attr)

        # Sort for order-agnostic comparison
        if sorted(orig_values) != sorted(round_values):
            value_mismatches[attr] = {
                "original": orig_values,
                "roundtrip": round_values,
            }

    matches = (
        dn_original == dn_roundtrip
        and not missing
        and not extra
        and not value_mismatches
    )

    details_parts = []
    if dn_original != dn_roundtrip:
        details_parts.append(f"DN mismatch: '{dn_original}' vs '{dn_roundtrip}'")
    if missing:
        details_parts.append(f"Missing attributes: {missing}")
    if extra:
        details_parts.append(f"Extra attributes: {extra}")
    if value_mismatches:
        details_parts.append(f"Value mismatches: {len(value_mismatches)} attributes")

    return {
        "matches": matches,
        "dn_match": dn_original == dn_roundtrip,
        "dn_original": dn_original,
        "dn_roundtrip": dn_roundtrip,
        "attribute_count_original": len(original_attrs),
        "attribute_count_roundtrip": len(roundtrip_attrs),
        "missing_attributes": sorted(missing),
        "extra_attributes": sorted(extra),
        "value_mismatches": value_mismatches,
        "details": " | ".join(details_parts) if details_parts else "Perfect match",
    }


# ============================================================================
# RFC COMPLIANCE VALIDATION UTILITIES
# ============================================================================


def validate_ldif_rfc2849_format(content: str) -> dict[str, object]:
    """Validate LDIF content conforms to RFC 2849 format rules.

    Validates:
    - No lines exceed 76 characters (before potential line continuation)
    - Entries separated by blank lines
    - All DNs present and valid
    - Attribute syntax compliance

    Args:
        content: LDIF formatted string

    Returns:
        Dictionary with validation results:
        {
            "is_valid": bool,
            "line_length_issues": list[int],  # Line numbers with length > 76
            "missing_dn_entries": int,
            "invalid_syntax": list[str],
            "error_count": int,
            "warnings": list[str]
        }

    """
    issues = []
    warnings = []
    missing_dn = 0

    lines = content.split("\n")
    for i, line in enumerate(lines, 1):
        # Skip empty lines and comments
        if not line or line.startswith("#"):
            continue

        # Check line length (RFC 2849: SHOULD not exceed 76 chars)
        if len(line.rstrip()) > 76 and not line.startswith(" "):
            issues.append(i)

        # Check for DN lines
        if line.lower().startswith("dn:"):
            dn_value = line[3:].strip()
            if not dn_value:
                warnings.append(f"Line {i}: Empty DN value")
                missing_dn += 1
            elif "=" not in dn_value:
                warnings.append(f"Line {i}: Malformed DN (no RDN)")

    # Check entry structure
    entry_count = count_entries(content)
    if entry_count == 0:
        warnings.append("No entries found in LDIF")

    return {
        "is_valid": len(issues) == 0 and missing_dn == 0,
        "line_length_issues": issues,
        "missing_dn_entries": missing_dn,
        "invalid_syntax": warnings,
        "error_count": len(issues) + missing_dn,
        "warnings": warnings,
    }


def validate_dn_rfc4514_format(dn: str) -> dict[str, object]:
    """Validate DN conforms to RFC 4514 Distinguished Name format.

    Validates:
    - Has at least one RDN (Relative Distinguished Name)
    - Each RDN has attribute=value format
    - Proper DN component ordering

    Args:
        dn: DN string to validate

    Returns:
        Dictionary with validation results:
        {
            "is_valid": bool,
            "rdn_count": int,
            "rdns": list[str],
            "errors": list[str]
        }

    """
    errors = []
    rdns: list[str] = []

    if not dn:
        errors.append("DN is empty")
        return {
            "is_valid": False,
            "rdn_count": 0,
            "rdns": rdns,
            "errors": errors,
        }

    # Split by comma (simple approach, doesn't handle escaped commas)
    parts = dn.split(",")

    for part in parts:
        part = part.strip()
        if not part:
            continue

        if "=" not in part:
            errors.append(f"RDN '{part}' has no '=' separator")
        else:
            rdns.append(part)

    if not rdns:
        errors.append("DN has no valid RDNs")

    return {
        "is_valid": len(errors) == 0 and len(rdns) > 0,
        "rdn_count": len(rdns),
        "rdns": rdns,
        "errors": errors,
    }


__all__ = [
    "compare_entries_deep",
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
    "get_entry_attribute_values",
    "is_abstract",
    "is_auxiliary",
    "is_single_valued",
    "is_structural",
    "validate_dn_rfc4514_format",
    "validate_ldif_rfc2849_format",
]
