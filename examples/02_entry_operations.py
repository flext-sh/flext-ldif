"""Example 2: DRY Entry Operations - Zero Code Bloat, Maximum Intelligence.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

flext-ldif enables intelligent operations with ZERO manual work:
- Auto-detect entry types from attributes (mail → inetOrgPerson, member → groupOfNames)
- Railway composition: build → filter → process → validate in ONE pipeline
- Batch operations with parallel processing and error aggregation
- Advanced filtering with type-safe predicates

Original: 235 lines | DRY Advanced: ~60 lines (75% reduction)
SRP: Each method does ONE thing, composition handles complexity
"""

from __future__ import annotations

from collections.abc import MutableSequence

from flext_core import r

from flext_ldif import ldif, m, t


class DRYEntryOperations:
    """DRY entry operations: intelligent builders + railway composition."""

    @staticmethod
    def advanced_filtering() -> r[MutableSequence[m.Ldif.Entry]]:
        """DRY advanced filtering: type-safe predicates + composition."""
        api = ldif.get_instance()
        entries_result = DRYEntryOperations.intelligent_builders()
        if entries_result.is_failure:
            return entries_result
        entries = entries_result.value
        filtered_it = api.filter_entries(
            entries,
            filter_func=lambda item: (
                item.attributes is not None
                and "IT" in item.attributes.get("departmentNumber", [])
            ),
        )
        if filtered_it.is_failure:
            return filtered_it
        return api.filter_entries(
            filtered_it.value,
            filter_func=lambda item: (
                item.attributes is not None
                and "@example.com"
                in (
                    item.attributes.get("mail", [""])[0]
                    if item.attributes.get("mail")
                    else ""
                )
            ),
        )

    @staticmethod
    def batch_processing() -> r[MutableSequence[t.ContainerMapping]]:
        """DRY batch processing: parallel transformation pipeline."""
        api = ldif.get_instance()
        return DRYEntryOperations.advanced_filtering().flat_map(
            lambda e: api.process_ldif(
                "transform", e, parallel=True, max_workers=4
            ).map(
                lambda res: [entry.model_dump() for entry in res],
            ),
        )

    @staticmethod
    def intelligent_builders() -> r[MutableSequence[m.Ldif.Entry]]:
        """DRY intelligent builders: auto-detect types from attributes."""
        api = ldif.get_instance()
        created_entries: list[m.Ldif.Entry] = []
        people_data: list[tuple[str, str, str, str]] = [
            ("Alice Johnson", "Johnson", "alice@example.com", "+1-555-0101"),
            ("Bob Smith", "Smith", "bob@example.com", "+1-555-0102"),
            ("Carol Davis", "Davis", "carol@example.com", "+1-555-0103"),
        ]
        for name, surname, email, phone in people_data:
            create_result = api.create_entry(
                dn=f"cn={name},ou=People,dc=example,dc=com",
                attributes={
                    "cn": name,
                    "sn": surname,
                    "mail": email,
                    "telephoneNumber": phone,
                },
            )
            if create_result.is_success:
                created_entries.append(create_result.value)

        if not created_entries:
            return r[MutableSequence[m.Ldif.Entry]].fail("No entries were created")

        return r[MutableSequence[m.Ldif.Entry]].ok(created_entries)
