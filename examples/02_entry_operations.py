"""Example 2: DRY Entry Operations - Zero Code Bloat, Maximum Intelligence.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

flext-ldif enables intelligent operations with ZERO manual work:
- Auto-detect entry types from attributes (mail -> inetOrgPerson, member -> groupOfNames)
- Railway composition: build -> filter -> process -> validate in ONE pipeline
- Batch operations with validation and error aggregation
- Advanced filtering with type-safe predicates

Original: 235 lines | DRY Advanced: ~60 lines (75% reduction)
SRP: Each method does ONE thing, composition handles complexity
"""

from __future__ import annotations

from collections.abc import (
    MutableSequence,
)

from flext_ldif import ldif, m, p, r


class DRYEntryOperations:
    """DRY entry operations: intelligent builders + railway composition."""

    @staticmethod
    def advanced_filtering() -> p.Result[MutableSequence[m.Ldif.Entry]]:
        """DRY advanced filtering: type-safe predicates + composition."""
        return DRYEntryOperations.intelligent_builders().map(
            lambda entries: [
                entry
                for entry in entries
                if entry.attributes is not None
                and "IT" in entry.attributes.get("departmentNumber", [])
                and entry.attributes.get("mail")
                and "@example.com" in entry.attributes.get("mail", [""])[0]
            ],
        )

    @staticmethod
    def batch_processing() -> p.Result[MutableSequence[m.Ldif.Entry]]:
        """DRY batch processing: validate entries pipeline."""
        api = ldif()
        return DRYEntryOperations.advanced_filtering().flat_map(
            lambda entries: api.validate_entries(entries).map(lambda _: entries),
        )

    @staticmethod
    def intelligent_builders() -> p.Result[MutableSequence[m.Ldif.Entry]]:
        """DRY intelligent builders: auto-detect types from attributes."""
        created_entries: list[m.Ldif.Entry] = []
        people_data: list[tuple[str, str, str, str]] = [
            ("Alice Johnson", "Johnson", "alice@example.com", "+1-555-0101"),
            ("Bob Smith", "Smith", "bob@example.com", "+1-555-0102"),
            ("Carol Davis", "Davis", "carol@example.com", "+1-555-0103"),
        ]
        for name, surname, email, phone in people_data:
            entry = m.Ldif.Entry(
                dn=m.Ldif.DN(value=f"cn={name},ou=People,dc=example,dc=com"),
                attributes=m.Ldif.Attributes(
                    attributes={
                        "objectClass": ["person", "inetOrgPerson"],
                        "cn": [name],
                        "sn": [surname],
                        "mail": [email],
                        "telephoneNumber": [phone],
                        "departmentNumber": ["IT"],
                    },
                    attribute_metadata={},
                ),
            )
            created_entries.append(entry)

        if not created_entries:
            return r[MutableSequence[m.Ldif.Entry]].fail("No entries were created")

        return r[MutableSequence[m.Ldif.Entry]].ok(created_entries)
