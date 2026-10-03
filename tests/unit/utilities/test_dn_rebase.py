"""Behavioral tests for modrdn-aware base-DN transformation.

``u.Ldif.transform_entry_base_dn`` must apply LDAP modrdn (deleteoldrdn)
semantics when an entry's own leftmost RDN changes during the rebase: the
naming attribute loses the old RDN value and gains the new one. Descendants
keep the pure suffix rebase; DN-valued attributes keep their rewrite.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT.
"""

from __future__ import annotations

import pytest
from flext_tests import tm

from tests import m, u

SOURCE = "dc=example,dc=invalid"
TARGET = "dc=r123,dc=algar,dc=local"


def _entry(dn: str, attributes: dict[str, list[str]] | None = None) -> m.Ldif.Entry:
    """Build a minimal LDIF entry model for transform tests.

    Returns:
        The resulting ``m.Ldif.Entry``.
    """
    return m.Ldif.Entry(
        dn=m.Ldif.DN(value=dn),
        attributes=m.Ldif.Attributes(
            attributes=attributes or {}, attribute_metadata={},
        ),
    )


@pytest.mark.unit
class TestsFlextLdifDnRebase:
    """Public contract of modrdn-aware transform_entry_base_dn."""

    @staticmethod
    def test_root_rdn_change_rewrites_naming_attribute() -> None:
        """The root's dc attribute carries only the new RDN value."""
        entry = _entry("dc=example,dc=invalid", {"dc": ["example"]})
        result = u.Ldif.transform_entry_base_dn(entry, SOURCE, TARGET)
        tm.that(tm.not_none(result.dn).value, eq="dc=r123,dc=algar,dc=local")
        tm.that(tm.not_none(result.attributes).attributes.get("dc", []), eq=["r123"])

    @staticmethod
    def test_descendant_keeps_own_rdn_and_attributes() -> None:
        """A descendant entry is only rebased; its cn stays untouched."""
        entry = _entry("cn=John,dc=example,dc=invalid", {"cn": ["John"], "sn": ["Doe"]})
        result = u.Ldif.transform_entry_base_dn(entry, SOURCE, TARGET)
        tm.that(tm.not_none(result.dn).value, eq=f"cn=John,{TARGET}")
        attrs = tm.not_none(result.attributes).attributes
        tm.that(attrs.get("cn", []), eq=["John"])
        tm.that(attrs.get("sn", []), eq=["Doe"])

    @staticmethod
    def test_multivalued_naming_attribute_keeps_sibling_values() -> None:
        """Deleteoldrdn removes only the old RDN value, keeping the others."""
        entry = _entry("dc=example,dc=invalid", {"dc": ["example", "other"]})
        result = u.Ldif.transform_entry_base_dn(entry, SOURCE, TARGET)
        values = tm.not_none(result.attributes).attributes.get("dc", [])
        tm.that(sorted(values), eq=["other", "r123"])

    @staticmethod
    def test_multipart_rdn_updates_every_naming_attribute() -> None:
        """cn=a+sn=b RDN changes rewrite both naming attributes."""
        source = f"cn=a+sn=b,{SOURCE}"
        target = f"cn=x+sn=y,{TARGET}"
        entry = _entry(source, {"cn": ["a"], "sn": ["b"]})
        result = u.Ldif.transform_entry_base_dn(entry, source, target)
        tm.that(tm.not_none(result.dn).value, eq=target)
        attrs = tm.not_none(result.attributes).attributes
        tm.that(attrs.get("cn", []), eq=["x"])
        tm.that(attrs.get("sn", []), eq=["y"])

    @staticmethod
    def test_escaped_rdn_value_round_trips_unescaped() -> None:
        """Escaped RDN values are removed/added in their unescaped form."""
        source = f"cn=a\\,b+sn=z,{SOURCE}"
        target = f"cn=c\\,d+sn=z,{TARGET}"
        entry = _entry(source, {"cn": ["a,b"], "sn": ["z"]})
        result = u.Ldif.transform_entry_base_dn(entry, source, target)
        attrs = tm.not_none(result.attributes).attributes
        tm.that(attrs.get("cn", []), eq=["c,d"])
        tm.that(attrs.get("sn", []), eq=["z"])

    @staticmethod
    def test_case_only_rdn_change_does_not_duplicate_value() -> None:
        """A case-variant new RDN replaces the value without duplicating it."""
        source = f"dc=example,{SOURCE}"
        target = f"dc=EXAMPLE,{TARGET}"
        entry = _entry(source, {"dc": ["example"]})
        result = u.Ldif.transform_entry_base_dn(entry, source, target)
        values = tm.not_none(result.attributes).attributes.get("dc", [])
        tm.that([v.lower() for v in values], eq=["example"])
        tm.that(len(values), eq=1)

    @staticmethod
    def test_rdn_type_change_moves_naming_value() -> None:
        """Changing the RDN attribute type removes the old pair and adds new."""
        source = f"cn=a,{SOURCE}"
        target = f"uid=a2,{TARGET}"
        entry = _entry(source, {"cn": ["a"]})
        result = u.Ldif.transform_entry_base_dn(entry, source, target)
        attrs = tm.not_none(result.attributes).attributes
        tm.that(attrs.get("cn", []), eq=[])
        tm.that(attrs.get("uid", []), eq=["a2"])

    @staticmethod
    def test_dn_valued_attributes_still_rebase() -> None:
        """Member values pointing under the old base are rewritten."""
        entry = _entry(
            f"cn=grp,{SOURCE}", {"cn": ["grp"], "member": [f"cn=John,{SOURCE}"]},
        )
        result = u.Ldif.transform_entry_base_dn(entry, SOURCE, TARGET)
        members = tm.not_none(result.attributes).attributes.get("member", [])
        tm.that(members, eq=[f"cn=John,{TARGET}"])

    @staticmethod
    def test_identity_transform_returns_same_values() -> None:
        """Source equal to target leaves DN and attributes untouched."""
        entry = _entry(f"cn=John,{SOURCE}", {"cn": ["John"]})
        result = u.Ldif.transform_entry_base_dn(entry, SOURCE, SOURCE)
        tm.that(tm.not_none(result.dn).value, eq=f"cn=John,{SOURCE}")
        tm.that(tm.not_none(result.attributes).attributes.get("cn", []), eq=["John"])

    @staticmethod
    def test_result_dn_revalidates_as_model() -> None:
        """The produced DN parses back through the DN model (round-trip)."""
        entry = _entry("dc=example,dc=invalid", {"dc": ["example"]})
        result = u.Ldif.transform_entry_base_dn(entry, SOURCE, TARGET)
        revalidated = m.Ldif.DN(value=tm.not_none(result.dn).value)
        tm.that(tm.not_none(revalidated).value, eq="dc=r123,dc=algar,dc=local")

    @staticmethod
    def test_unparseable_new_rdn_fails_loud() -> None:
        """A broken new root DN fails loud (RFC 4514) without corrupting."""
        entry = _entry(SOURCE, {"dc": ["example"]})
        with pytest.raises(ValueError, match="DN"):
            u.Ldif.transform_entry_base_dn(
                entry, SOURCE, f"brokenrdn,{TARGET.split(',', 1)[1]}",
            )
