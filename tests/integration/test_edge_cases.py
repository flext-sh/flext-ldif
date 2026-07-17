"""Edge case and boundary condition tests.

Behavioral test suite for the public ``ldif()`` client contract under edge and
boundary inputs. Every assertion targets observable public behavior only:

- The ``r[T]`` outcome of ``parse_ldif`` / ``write`` (``.success`` / ``.value``).
- Public model state via the public API (``ParseResponse.entries``,
  ``Entry.dn_str``, ``Entry.attributes_dict``, ``WriteResponse.content``).

No private attributes, internal collaborators, or implementation data
structures are inspected.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
from flext_tests import tm

from flext_ldif import ldif

if TYPE_CHECKING:
    from tests import p

_ZERO_WIDTH = "zero" + "\u200b" + "width" + "\u200b" + "spaces"


class TestsFlextLdifEdgeCases:
    """Behavioral edge-case coverage for the public LDIF client contract."""

    @pytest.fixture
    def api(self) -> p.Ldif.Client:
        """Public LDIF client instance."""
        return ldif()

    # -- Empty / minimal content -------------------------------------------

    @pytest.mark.parametrize(
        ("label", "content"),
        [
            ("empty", ""),
            ("whitespace", "   \n\n  \t\n  "),
            ("comments", "# Comment 1\n# Comment 2\n# Comment 3\n"),
        ],
    )
    def test_content_without_entries_parses_to_empty_list(
        self,
        api: p.Ldif.Client,
        label: str,
        content: str,
    ) -> None:
        """Empty, whitespace-only, and comment-only input yield zero entries."""
        result = api.parse_ldif(content)

        tm.ok(result)
        tm.that(result.value.entries, eq=[])

    def test_single_entry_with_only_dn_preserves_dn(
        self,
        api: p.Ldif.Client,
    ) -> None:
        """A minimal DN-only entry yields exactly one entry with that DN."""
        result = api.parse_ldif("dn: cn=Single,dc=example,dc=com\n")

        tm.ok(result)
        entries = result.value.entries
        tm.that(len(entries), eq=1)
        tm.that(entries[0].dn_str.lower(), eq="cn=single,dc=example,dc=com")

    def test_single_entry_with_one_attribute_preserves_value(
        self,
        api: p.Ldif.Client,
    ) -> None:
        """DN plus a single attribute round-trips the attribute value."""
        result = api.parse_ldif(
            "dn: cn=OneAttr,dc=example,dc=com\ncn: OneAttr\n",
        )

        tm.ok(result)
        entries = result.value.entries
        tm.that(len(entries), eq=1)
        tm.that(entries[0].attributes_dict["cn"], eq=["OneAttr"])

    # -- Large / complex content -------------------------------------------

    def test_entry_with_many_attribute_values_preserves_all(
        self,
        api: p.Ldif.Client,
    ) -> None:
        """A multi-valued attribute with 100 values preserves every value."""
        expected = [f"user{i}@example.com" for i in range(100)]
        values = "".join(f"mail: {v}\n" for v in expected)
        content = (
            "dn: cn=ManyValues,dc=example,dc=com\n"
            "objectClass: person\ncn: ManyValues\n" + values
        )

        result = api.parse_ldif(content)

        tm.ok(result)
        entries = result.value.entries
        tm.that(len(entries), eq=1)
        tm.that(entries[0].attributes_dict["mail"], eq=expected)

    def test_entry_preserves_all_distinct_attribute_names(
        self,
        api: p.Ldif.Client,
    ) -> None:
        """Every distinct attribute in the input is present after parsing."""
        content = (
            "dn: cn=Multi,dc=example,dc=com\n"
            "objectClass: person\ncn: Multi\nsn: Surname\n"
            "mail: multi@example.com\ntelephoneNumber: 12345\n"
            "description: an entry\n"
        )

        result = api.parse_ldif(content)

        tm.ok(result)
        attrs = result.value.entries[0].attributes_dict
        assert set(attrs) >= {
            "objectClass",
            "cn",
            "sn",
            "mail",
            "telephoneNumber",
            "description",
        }

    def test_very_long_single_value_preserved_intact(
        self,
        api: p.Ldif.Client,
    ) -> None:
        """A 10KB attribute value is preserved without truncation."""
        long_value = "x" * 10_000
        content = (
            "dn: cn=LongValue,dc=example,dc=com\n"
            "objectClass: person\ncn: LongValue\n"
            f"description: {long_value}\n"
        )

        result = api.parse_ldif(content)

        tm.ok(result)
        tm.that(
            result.value.entries[0].attributes_dict["description"],
            eq=[
                long_value,
            ],
        )

    def test_deeply_nested_dn_hierarchy_preserved(
        self,
        api: p.Ldif.Client,
    ) -> None:
        """A DN with 10+ nesting levels is preserved verbatim."""
        deep_dn = ",".join(f"ou=level{i}" for i in range(10))
        full_dn = f"cn=DeepNest,{deep_dn},dc=example,dc=com"
        content = f"dn: {full_dn}\nobjectClass: person\ncn: DeepNest\n"

        result = api.parse_ldif(content)

        tm.ok(result)
        entries = result.value.entries
        tm.that(len(entries), eq=1)
        tm.that(entries[0].dn_str.lower(), eq=full_dn.lower())

    # -- Boundary values ----------------------------------------------------

    def test_single_character_components_parse(
        self,
        api: p.Ldif.Client,
    ) -> None:
        """Single-character DN and attribute values are accepted and kept."""
        result = api.parse_ldif("dn: cn=A,dc=B\nobjectClass: X\ncn: A\nsn: B\n")

        tm.ok(result)
        entry = result.value.entries[0]
        tm.that(entry.attributes_dict["cn"], eq=["A"])
        tm.that(entry.attributes_dict["sn"], eq=["B"])

    @pytest.mark.parametrize(
        ("attribute", "value"),
        [("sn", "*"), ("mail", "+"), ("description", "-")],
    )
    def test_special_single_character_values_preserved(
        self,
        api: p.Ldif.Client,
        attribute: str,
        value: str,
    ) -> None:
        """Special single-character values are preserved exactly."""
        content = (
            f"dn: cn=Special,dc=example,dc=com\ncn: Special\n{attribute}: {value}\n"
        )

        result = api.parse_ldif(content)

        tm.ok(result)
        tm.that(result.value.entries[0].attributes_dict[attribute], eq=[value])

    def test_many_rdn_components_preserved(
        self,
        api: p.Ldif.Client,
    ) -> None:
        """A DN with many RDN components is preserved verbatim."""
        components = ",".join(f"ou=ou{i}" for i in range(20))
        full_dn = f"cn=MaxRDN,{components},dc=example,dc=com"
        content = f"dn: {full_dn}\nobjectClass: person\ncn: MaxRDN\n"

        result = api.parse_ldif(content)

        tm.ok(result)
        tm.that(result.value.entries[0].dn_str.lower(), eq=full_dn.lower())

    def test_minimum_single_rdn_dn_parses(
        self,
        api: p.Ldif.Client,
    ) -> None:
        """The shortest valid single-RDN DN parses to one preserved entry."""
        result = api.parse_ldif("dn: cn=MinDN\nobjectClass: top\ncn: MinDN\n")

        tm.ok(result)
        entries = result.value.entries
        tm.that(len(entries), eq=1)
        tm.that(entries[0].dn_str.lower(), eq="cn=mindn")

    # -- Unicode / encoding boundaries -------------------------------------

    @pytest.mark.parametrize(
        ("label", "text"),
        [
            ("bmp", "café, naïve, résumé, 中文, 日本語, العربية"),
            ("supplementary", "emoji: 😀 🎉 🚀"),
            ("zero_width", _ZERO_WIDTH),
            ("combining", "combining: é (e + ́)"),
        ],
    )
    def test_unicode_description_preserved_exactly(
        self,
        api: p.Ldif.Client,
        label: str,
        text: str,
    ) -> None:
        """Unicode across all ranges is preserved exactly in parsed values."""
        content = (
            f"dn: cn=Unicode,dc=example,dc=com\ncn: Unicode\ndescription: {text}\n"
        )

        result = api.parse_ldif(content)

        tm.ok(result)
        tm.that(result.value.entries[0].attributes_dict["description"], eq=[text])

    def test_base64_encoded_value_is_decoded(
        self,
        api: p.Ldif.Client,
    ) -> None:
        """A ``::`` base64 attribute value is decoded to its plain text."""
        content = "dn: cn=B64,dc=example,dc=com\ncn: B64\ndescription:: aGVsbG8=\n"

        result = api.parse_ldif(content)

        tm.ok(result)
        tm.that(
            result.value.entries[0].attributes_dict["description"],
            eq=[
                "hello",
            ],
        )

    # -- Roundtrip invariants ----------------------------------------------

    def test_empty_roundtrip_produces_no_entries(
        self,
        api: p.Ldif.Client,
    ) -> None:
        """Parsing empty input then writing yields empty/version-only output."""
        result = api.parse_ldif("")
        tm.ok(result)
        tm.that(result.value.entries, eq=[])

        write_result = api.write(result.value.entries)
        tm.ok(write_result)
        written = write_result.value.content
        tm.that(written, none=False)
        assert not written.strip() or written.strip() == "version: 1"

    def test_single_entry_roundtrip_preserves_dn_and_value(
        self,
        api: p.Ldif.Client,
    ) -> None:
        """Parse -> write -> parse preserves the entry DN and attribute."""
        result = api.parse_ldif("dn: cn=Test,dc=example,dc=com\ncn: Test\n")
        tm.ok(result)

        write_result = api.write(result.value.entries)
        tm.ok(write_result)
        content = write_result.value.content
        tm.that(content, none=False)

        roundtrip = api.parse_ldif(content)
        tm.ok(roundtrip)
        entries = roundtrip.value.entries
        tm.that(len(entries), eq=1)
        tm.that(entries[0].dn_str.lower(), eq="cn=test,dc=example,dc=com")
        tm.that(entries[0].attributes_dict["cn"], eq=["Test"])

    def test_many_entries_roundtrip_preserves_count_and_dns(
        self,
        api: p.Ldif.Client,
    ) -> None:
        """A 100-entry roundtrip preserves both the count and every DN."""
        source = "\n\n".join(
            f"dn: cn=Entry{i},dc=example,dc=com\n"
            f"objectClass: person\ncn: Entry{i}\nsn: Test{i}"
            for i in range(100)
        )
        result = api.parse_ldif(source)
        tm.ok(result)
        original_dns = [e.dn_str.lower() for e in result.value.entries]
        tm.that(len(original_dns), eq=100)

        write_result = api.write(result.value.entries)
        tm.ok(write_result)
        content = write_result.value.content
        tm.that(content, none=False)

        roundtrip = api.parse_ldif(content)
        tm.ok(roundtrip)
        roundtrip_dns = [e.dn_str.lower() for e in roundtrip.value.entries]
        tm.that(roundtrip_dns, eq=original_dns)


__all__: list[str] = ["TestsFlextLdifEdgeCases"]
