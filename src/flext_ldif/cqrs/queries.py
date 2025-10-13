"""CQRS Query Definitions for FLEXT-LDIF.

This module defines query classes for read operations that retrieve LDIF data.
Queries represent user intentions to read state (validate, analyze, filter, extract).

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class ValidateEntriesQuery(BaseModel):
    """Query to validate LDIF entries against RFC and schema rules.

    Represents the intention to validate LDIF entries for correctness,
    optionally checking against a schema definition.

    Attributes:
        entries: List of LDIF Entry models to validate
        schema_definition: Optional schema definition for validation

    Example:
        query = ValidateEntriesQuery(
            entries=[entry1, entry2],
            schema_definition={"attributes": {...}, "objectclasses": {...}}
        )

    """

    entries: list  # FlextLdifModels.Entry - avoid circular import
    schema_definition: dict[str, Any] | None = Field(
        default=None,
        description="Optional schema definition for validation",
    )


class AnalyzeEntriesQuery(BaseModel):
    """Query to analyze LDIF entries and generate statistics.

    Represents the intention to analyze LDIF entries and extract
    statistics about entry types, attributes, and structure.

    Attributes:
        entries: List of LDIF Entry models to analyze

    Example:
        query = AnalyzeEntriesQuery(
            entries=[entry1, entry2, entry3]
        )

    """

    entries: list  # FlextLdifModels.Entry


class FilterEntriesQuery(BaseModel):
    """Query to filter LDIF entries by various criteria.

    Represents the intention to filter LDIF entries based on
    object class, DN pattern, or other criteria.

    Attributes:
        entries: List of LDIF Entry models to filter
        objectclass: Optional object class filter
        dn_pattern: Optional DN pattern filter (regex)

    Example:
        # Filter by object class
        query = FilterEntriesQuery(
            entries=[entry1, entry2, entry3],
            objectclass="person"
        )

        # Filter by DN pattern
        query = FilterEntriesQuery(
            entries=[entry1, entry2, entry3],
            dn_pattern="ou=People,.*"
        )

    """

    entries: list  # FlextLdifModels.Entry
    objectclass: str | None = Field(
        default=None,
        description="Optional object class to filter by",
        max_length=255,
    )
    dn_pattern: str | None = Field(
        default=None,
        description="Optional DN pattern (regex) to filter by",
        max_length=1024,
    )


class ExtractAclsQuery(BaseModel):
    """Query to extract ACL rules from an LDIF entry.

    Represents the intention to extract and parse ACL (Access Control List)
    rules from an entry's attributes.

    Attributes:
        entry: LDIF Entry model to extract ACLs from

    Example:
        query = ExtractAclsQuery(
            entry=entry_with_acls
        )

    """

    entry: Any  # FlextLdifModels.Entry - avoid circular import


class ConvertEntryToDictQuery(BaseModel):
    """Query to convert LDIF entry to dictionary format.

    Represents the intention to convert an Entry model to
    a dictionary representation for serialization or processing.

    Attributes:
        entry: LDIF Entry model to convert

    Example:
        query = ConvertEntryToDictQuery(
            entry=entry
        )

    """

    entry: Any  # FlextLdifModels.Entry


class ConvertEntriesToDictsQuery(BaseModel):
    """Query to convert multiple LDIF entries to dictionary format.

    Represents the intention to batch convert Entry models to
    dictionary representations.

    Attributes:
        entries: List of LDIF Entry models to convert

    Example:
        query = ConvertEntriesToDictsQuery(
            entries=[entry1, entry2, entry3]
        )

    """

    entries: list  # FlextLdifModels.Entry


__all__ = [
    "AnalyzeEntriesQuery",
    "ConvertEntriesToDictsQuery",
    "ConvertEntryToDictQuery",
    "ExtractAclsQuery",
    "FilterEntriesQuery",
    "ValidateEntriesQuery",
]
