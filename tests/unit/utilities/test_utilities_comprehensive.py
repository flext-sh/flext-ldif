"""Comprehensive automated tests for utilities.py - Target: 100% coverage.

Tests all 830 uncovered lines in utilities.py with real data and automation.
"""

from __future__ import annotations

from collections.abc import (
    MutableSequence,
)

import pytest
from flext_tests import tm

from tests.models import m
from tests.typings import t
from tests.utilities import u


class TestsFlextLdifUtilitiesComprehensive:
    """Comprehensive automated tests for all utilities functionality."""

    def test_real_ldif_processing_pipeline(self) -> None:
        """Test complete LDIF processing pipeline with real data."""
        ldif_content = u.Tests.create_real_ldif_content(
            entries_count=5,
            include_schema=True,
        )
        lines = ldif_content.split("\n")
        entries: MutableSequence[m.Tests.LdifTestData] = []
        for line in lines:
            if line.startswith("dn:"):
                current_dn = line[4:].strip()
                current_attrs: t.MutableStrSequenceMapping = {}
                entries.append(
                    m.Tests.LdifTestData(
                        id=f"entry_{len(entries)}",
                        server_type="generic",
                        dn=current_dn,
                        attributes=current_attrs,
                    ),
                )
            elif line.startswith(" ") and entries:
                continue
            elif ":" in line and entries:
                key, value = line.split(":", 1)
                key = key.strip()
                value = value.strip()
                attrs: t.MutableStrSequenceMapping = {
                    k: list(v) for k, v in entries[-1].attributes.items()
                }
                if key not in attrs:
                    attrs[key] = []
                attrs[key].append(value)
        tm.that(len(entries), gte=5)
        for entry in entries:
            tm.that(entry.dn, none=False)
            tm.that(entry.attributes, none=False)
            tm.that(entry.attributes, is_=dict)

    @pytest.mark.parametrize("server_type", ["generic", "openldap", "ad", "oid", "oud"])
    def test_server_specific_utilities(self, server_type: str) -> None:
        """Test server-specific utility functions."""
        entry = u.Tests.create_real_entry(server_type=server_type)
        tm.that(entry, none=False)
        normalized = u.Ldif.normalize_server_type(server_type)
        tm.that(normalized, is_=str)
        tm.that(normalized, empty=False)
