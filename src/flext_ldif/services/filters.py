"""Filters service - LDIF Entry Filtering Operations."""

from __future__ import annotations

from flext_ldif import c, m, p, r, s, t, u


class FlextLdifFilters(s):
    """LDIF entry filtering service."""

    @classmethod
    def _check_schema_oid(
        cls,
        attrs: t.MutableStrSequenceMapping,
        attr_keys: t.StrPair,
        allowed_set: frozenset[str],
    ) -> tuple[bool, bool]:
        """Check if schema OID matches allowed set."""
        key1, key2 = attr_keys
        if key1 not in attrs and key2 not in attrs:
            return (False, True)
        oid = cls._extract_oid_from_schema_attr(attrs.get(key1, attrs.get(key2, [])))
        if oid and allowed_set and (oid not in allowed_set):
            return (True, False)
        return (True, True)

    @classmethod
    def _extract_allowed_oids(
        cls,
        allowed_oids: m.Ldif.WhitelistRules | t.MutableFrozensetMapping,
    ) -> tuple[frozenset[str], frozenset[str], frozenset[str], frozenset[str]]:
        """Extract allowed OID sets from mapping."""
        if isinstance(allowed_oids, m.Ldif.WhitelistRules):
            return (
                frozenset(allowed_oids.allowed_attribute_oids),
                frozenset(allowed_oids.allowed_objectclass_oids),
                frozenset(allowed_oids.allowed_matchingrule_oids),
                frozenset(allowed_oids.allowed_matchingruleuse_oids),
            )
        return (
            allowed_oids.get("allowed_attribute_oids", frozenset()),
            allowed_oids.get("allowed_objectclass_oids", frozenset()),
            allowed_oids.get("allowed_matchingrule_oids", frozenset()),
            allowed_oids.get("allowed_matchingruleuse_oids", frozenset()),
        )

    @classmethod
    def _extract_oid_from_schema_attr(
        cls,
        values: t.MutableSequenceOf[str],
    ) -> str | None:
        """Extract OID from schema attribute value."""
        if not values:
            return None
        value = values[0] if values else ""
        value = value.strip()
        if value.startswith("("):
            parts = value[1:].strip().split()
            if parts:
                oid = parts[0]
                if oid and oid[0].isdigit():
                    return oid
        return None

    @classmethod
    def _should_include_entry(
        cls,
        entry: m.Ldif.Entry,
        allowed_oids: m.Ldif.WhitelistRules | t.MutableFrozensetMapping,
    ) -> bool:
        """Check if entry should be included based on OID filters."""
        attrs = entry.attributes
        if attrs is None:
            return True
        if getattr(attrs, "attributes", None) is not None:
            attrs_dict: t.MutableStrSequenceMapping = attrs.attributes
        else:
            return True
        allowed_attr, allowed_oc, allowed_mr, allowed_mru = cls._extract_allowed_oids(
            allowed_oids,
        )
        is_attr, include_attr = cls._check_schema_oid(
            attrs_dict,
            ("attributeTypes", "attributetypes"),
            allowed_attr,
        )
        is_oc, include_oc = cls._check_schema_oid(
            attrs_dict,
            ("objectClasses", "objectclasses"),
            allowed_oc,
        )
        is_mr, include_mr = cls._check_schema_oid(
            attrs_dict,
            ("matchingRules", "matchingrules"),
            allowed_mr,
        )
        is_mru, include_mru = cls._check_schema_oid(
            attrs_dict,
            ("matchingRuleUse", "matchingruleuse"),
            allowed_mru,
        )
        is_schema_entry = is_attr or is_oc or is_mr or is_mru
        should_include = include_attr and include_oc and include_mr and include_mru
        return not is_schema_entry or should_include

    @classmethod
    def filter_schema_by_oids(
        cls,
        entries: t.MutableSequenceOf[m.Ldif.Entry],
        allowed_oids: m.Ldif.WhitelistRules | t.MutableFrozensetMapping,
    ) -> p.Result[t.MutableSequenceOf[m.Ldif.Entry]]:
        """Filter schema entries by allowed OIDs."""
        try:
            allowed_attr, allowed_oc, allowed_mr, allowed_mru = (
                cls._extract_allowed_oids(allowed_oids)
            )
            if not any([allowed_attr, allowed_oc, allowed_mr, allowed_mru]):
                return r[t.MutableSequenceOf[m.Ldif.Entry]].ok(entries)
            filtered: t.MutableSequenceOf[m.Ldif.Entry] = [
                entry
                for entry in entries
                if cls._should_include_entry(entry, allowed_oids)
            ]
            cls._get_or_create_logger().debug(
                "Filtered schema entries by OIDs",
                total_entries=len(entries),
                filtered_count=len(filtered),
            )
            return r[t.MutableSequenceOf[m.Ldif.Entry]].ok(filtered)
        except c.Ldif.EXC_LDIF_PARSE as e:
            cls._get_or_create_logger().exception(
                "Failed to filter schema entries by OIDs",
            )
            return r[t.MutableSequenceOf[m.Ldif.Entry]].fail_op("Schema OID filter", e)

    @classmethod
    def filter_entry_attributes(
        cls,
        entry: m.Ldif.Entry | p.Ldif.Entry,
        forbidden_attrs: t.StrSequence,
        forbidden_ocs: t.StrSequence,
    ) -> m.Ldif.Entry:
        """Strip forbidden attributes and objectClasses from an entry."""
        filtered_entry: m.Ldif.Entry = u.Ldif.as_entry(entry)
        if entry.attributes and forbidden_attrs:
            attrs_dict = entry.attributes.attributes
            forbidden_set = {attr.lower() for attr in forbidden_attrs}
            attrs_to_remove: t.StrSequence = [
                k for k in attrs_dict if k.lower() in forbidden_set
            ]
            if attrs_to_remove:
                filtered_attrs = {
                    k: v for k, v in attrs_dict.items() if k not in attrs_to_remove
                }
                filtered_entry = filtered_entry.model_copy(
                    update={
                        "attributes": m.Ldif.Attributes.model_validate({
                            "attributes": filtered_attrs,
                        }),
                    },
                )
        if forbidden_ocs and filtered_entry.attributes is not None:
            oc_attrs = filtered_entry.attributes.attributes
            forbidden_ocs_lower = {oc.lower() for oc in forbidden_ocs}
            oc_key: str | None = next(
                (k for k in oc_attrs if k.lower() == "objectclass"),
                None,
            )
            if oc_key is not None:
                filtered_ocs: list[str] = [
                    v for v in oc_attrs[oc_key] if v.lower() not in forbidden_ocs_lower
                ]
                updated = dict(oc_attrs)
                if filtered_ocs:
                    updated[oc_key] = filtered_ocs
                else:
                    updated.pop(oc_key, None)
                filtered_entry = filtered_entry.model_copy(
                    update={
                        "attributes": m.Ldif.Attributes.model_validate({
                            "attributes": updated,
                        }),
                    },
                )
        return filtered_entry

    @classmethod
    def filter_schema_attribute_values(
        cls,
        entry: m.Ldif.Entry | p.Ldif.Entry,
        allowed_oids: t.MappingKV[str, frozenset[str]],
    ) -> m.Ldif.Entry:
        """Filter individual OID values within schema entry attributes."""
        concrete: m.Ldif.Entry = u.Ldif.as_entry(entry)
        if concrete.attributes is None:
            return concrete
        attrs_dict = concrete.attributes.attributes
        updated_attrs: dict[str, list[str]] = {
            k: list(v) for k, v in attrs_dict.items()
        }
        changed = False
        for attr_name in list(updated_attrs):
            oid_set = allowed_oids.get(attr_name.lower())
            if oid_set is None:
                continue
            original = updated_attrs[attr_name]
            filtered: list[str] = [
                value
                for value in original
                if (oid := cls._extract_oid_from_schema_attr([value])) is None
                or oid in oid_set
            ]
            if filtered != original:
                changed = True
            if filtered:
                updated_attrs[attr_name] = filtered
            else:
                del updated_attrs[attr_name]
        if not changed:
            return concrete
        copied: m.Ldif.Entry = concrete.model_copy(
            update={
                "attributes": m.Ldif.Attributes.model_validate({
                    "attributes": updated_attrs,
                }),
            },
        )
        return copied


__all__: list[str] = ["FlextLdifFilters"]
