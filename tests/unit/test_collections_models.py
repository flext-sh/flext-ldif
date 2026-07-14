"""Unit tests for LDIF collection-oriented models."""

from __future__ import annotations

import pytest
from flext_tests import tm

from tests import TestsFlextLdifUtilities as u, c, m, t


class TestsFlextLdifCollectionsModels:
    """Cover DynamicCounts, SchemaContent, and FlexibleCategories behavior."""

    @staticmethod
    def _entry(cn_value: str) -> m.Ldif.Entry:
        return u.Tests.create_real_entry(
            dn=c.Tests.ENTRIES_DN_VALID,
            attributes={
                c.Tests.NAME_OBJECTCLASS: list(c.Tests.ENTRIES_OBJECTCLASS_PERSON),
                c.Tests.NAME_CN: [cn_value],
                c.Tests.NAME_SN: [c.Tests.ATTR_VALUE_TEST],
            },
        )

    def test_dynamic_counts_exposes_count_mapping_contract(self) -> None:
        counts = m.Ldif.DynamicCounts.model_validate({
            c.Ldif.Category.USERS.value: 3,
            c.Ldif.Category.GROUPS.value: "2",
            c.Ldif.Category.SCHEMA.value: True,
        })

        tm.that(len(counts), eq=3)
        tm.that(c.Ldif.Category.USERS.value in counts, eq=True)
        tm.that(counts[c.Ldif.Category.USERS.value], eq=3)
        tm.that(counts[c.Ldif.Category.GROUPS.value], eq=2)
        tm.that(counts[c.Ldif.Category.SCHEMA.value], eq=0)
        tm.that(counts.get(c.Ldif.Category.ACL.value, 9), eq=9)
        tm.that(
            counts.items(),
            eq=[
                (c.Ldif.Category.USERS.value, 3),
                (c.Ldif.Category.GROUPS.value, 2),
                (c.Ldif.Category.SCHEMA.value, 0),
            ],
        )

    def test_dynamic_counts_missing_key_raises_key_error(self) -> None:
        counts = m.Ldif.DynamicCounts()

        with pytest.raises(KeyError, match="missing"):
            _ = counts["missing"]

    def test_dynamic_counts_update_count_tracks_new_extra_key(self) -> None:
        counts = m.Ldif.DynamicCounts()

        counts.update_count(c.Ldif.Category.REJECTED.value, 4)

        tm.that(counts.get(c.Ldif.Category.REJECTED.value), eq=4)
        tm.that(counts[c.Ldif.Category.REJECTED.value], eq=4)

    def test_schema_content_accepts_empty_sequences(self) -> None:
        schema_content = m.Ldif.SchemaContent.model_validate({
            "attributes": [],
            "object_classes": [],
        })

        tm.that(schema_content.attributes, eq=[])
        tm.that(schema_content.object_classes, eq=[])

    def test_flexible_categories_getitem_auto_initializes_bucket(self) -> None:
        categories = m.Ldif.FlexibleCategories()

        users_entries = categories[c.Ldif.Category.USERS.value]

        tm.that(users_entries, eq=[])
        tm.that(c.Ldif.Category.USERS.value in categories, eq=True)

    def test_flexible_categories_setitem_copies_entries(self) -> None:
        categories = m.Ldif.FlexibleCategories()
        original_entries: t.MutableSequenceOf[m.Ldif.Entry] = [self._entry("alpha")]

        categories[c.Ldif.Category.USERS.value] = original_entries
        original_entries.append(self._entry("beta"))

        stored_entries = categories[c.Ldif.Category.USERS.value]
        tm.that(len(stored_entries), eq=1)
        tm.that(stored_entries[0].dn_str, eq=c.Tests.ENTRIES_DN_VALID)

    def test_flexible_categories_add_entries_appends_to_existing_bucket(self) -> None:
        categories = m.Ldif.FlexibleCategories()

        categories.add_entries(c.Ldif.Category.USERS.value, [self._entry("alpha")])
        categories.add_entries(c.Ldif.Category.USERS.value, [self._entry("beta")])

        stored_entries = categories.get(c.Ldif.Category.USERS.value)
        tm.that(len(stored_entries), eq=2)

    def test_flexible_categories_exposes_mapping_views_and_hash_error(self) -> None:
        categories = m.Ldif.FlexibleCategories()
        default_entries = [self._entry("fallback")]

        categories[c.Ldif.Category.GROUPS.value] = [self._entry("groups")]

        tm.that(
            categories.get(c.Ldif.Category.ACL.value, default_entries),
            eq=default_entries,
        )
        tm.that(list(categories.keys()), eq=[c.Ldif.Category.GROUPS.value])
        tm.that(len(list(categories.values())), eq=1)
        tm.that(len(list(categories.items())), eq=1)

        with pytest.raises(TypeError, match="unhashable"):
            _ = hash(categories)

    def test_oid_acl_rule_models_carry_typed_subjects(self) -> None:
        subject = m.Ldif.OidAclSubject(
            subject_type="group",
            value="cn=admins,dc=ctbc",
            permissions=("add", "delete", "browse"),
        )
        rule = m.Ldif.OidAclRule(
            dn="dc=ctbc",
            acl_type="orclaci",
            target_type="entry",
            subjects=(subject,),
            raw_line="orclaci: access to entry by group=...",
        )

        tm.that(rule.acl_type, eq="orclaci")
        tm.that(rule.target_type, eq="entry")
        tm.that(rule.target_attrs, eq="*")
        tm.that(rule.target_filter is None, eq=True)
        tm.that(len(rule.subjects), eq=1)
        tm.that(rule.subjects[0].subject_type, eq="group")
        tm.that(rule.subjects[0].permissions, eq=("add", "delete", "browse"))

    def test_aci_rule_models_carry_typed_allows(self) -> None:
        allow = m.Ldif.AciAllow(
            subject_type="groupdn",
            subject_value="ldap:///cn=admins,dc=ctbc",
            permissions=("read", "search", "add", "delete"),
        )
        aci = m.Ldif.AciRule(
            dn="dc=ctbc",
            targetattr="*",
            targetscope="base",
            acl_name="admins Entry by admins",
            allows=(allow,),
        )

        tm.that(aci.targetattr, eq="*")
        tm.that(aci.targetscope, eq="base")
        tm.that(aci.targetfilter is None, eq=True)
        tm.that(len(aci.allows), eq=1)
        tm.that(aci.allows[0].subject_type, eq="groupdn")
        tm.that(aci.allows[0].permissions, eq=("read", "search", "add", "delete"))
