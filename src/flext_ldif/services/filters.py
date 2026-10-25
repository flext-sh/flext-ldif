"""Filters service - LDIF Entry Filtering Operations.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_ldif import c, m, p, r, s, t, u


class FlextLdifFilters(s[p.Ldif.Response]):
    """LDIF entry filtering service."""

    @classmethod
    def _check_schema_oid(
        cls,
        attrs: t.MutableStrSequenceMapping,
        attr_keys: t.StrPair,
        allowed_set: frozenset[str],
    ) -> tuple[bool, bool]:
        """Check if schema OID matches allowed set.

        Returns:
            The resulting ``tuple[bool, bool]``.

        """
        key1, key2 = attr_keys
        if key1 not in attrs and key2 not in attrs:
            return (False, True)
        values = attrs.get(key1, attrs.get(key2, []))
        oid = cls._extract_oid_from_schema_attr(values[0]) if values else None
        if oid and allowed_set and (oid not in allowed_set):
            return (True, False)
        return (True, True)

    @classmethod
    def _extract_allowed_oids(
        cls,
        allowed_oids: m.Ldif.WhitelistRules | t.FrozensetMapping,
    ) -> t.FrozensetMapping:
        """Extract allowed OID sets keyed by canonical schema attribute names.

        Returns:
            The resulting ``t.FrozensetMapping``.

        """
        if isinstance(allowed_oids, m.Ldif.WhitelistRules):
            return allowed_oids.schema_oid_filters
        return {
            attr_name: allowed_oids.get(attr_name, c.Ldif.EMPTY_STR_FROZENSET)
            for _, attr_name in c.Ldif.WHITELIST_RULE_SCHEMA_ATTRIBUTE_KEYS
        }

    @classmethod
    def _extract_oid_from_schema_attr(
        cls,
        value: str,
    ) -> str | None:
        """Extract OID from schema attribute value.

        Returns:
            The resulting ``str | None``.

        """
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
        allowed_oids: m.Ldif.WhitelistRules | t.FrozensetMapping,
    ) -> bool:
        """Check if entry should be included based on OID filters.

        Returns:
            The resulting ``bool``.

        """
        attrs = entry.attributes
        if attrs is None:
            return True
        if getattr(attrs, "attributes", None) is not None:
            attrs_dict: t.MutableStrSequenceMapping = attrs.attributes
        else:
            return True
        allowed_oid_map = cls._extract_allowed_oids(allowed_oids)
        checks = [
            cls._check_schema_oid(attrs_dict, attr_keys, allowed_oid_map[attr_keys[1]])
            for attr_keys in c.Ldif.SCHEMA_OID_ATTRIBUTE_KEYS
        ]
        is_schema_entry = any(is_schema for is_schema, _ in checks)
        should_include = all(include_entry for _, include_entry in checks)
        return not is_schema_entry or should_include

    @classmethod
    def filter_schema_by_oids(
        cls,
        entries: t.MutableSequenceOf[m.Ldif.Entry],
        allowed_oids: m.Ldif.WhitelistRules | t.FrozensetMapping,
    ) -> p.Result[t.MutableSequenceOf[m.Ldif.Entry]]:
        """Filter schema entries by allowed OIDs.

        Returns:
            The resulting ``p.Result[t.MutableSequenceOf[m.Ldif.Entry]]``.

        """
        try:
            allowed_oid_map = cls._extract_allowed_oids(allowed_oids)
            if not any(allowed_oid_map.values()):
                return r[t.MutableSequenceOf[m.Ldif.Entry]].ok(entries)
            filtered: t.MutableSequenceOf[m.Ldif.Entry] = [
                entry
                for entry in entries
                if cls._should_include_entry(entry, allowed_oid_map)
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
        """Strip forbidden attributes and objectClasses from an entry.

        Returns:
            The resulting ``m.Ldif.Entry``.

        """
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
                (
                    k
                    for k in oc_attrs
                    if k.lower() == c.Ldif.DictKeys.OBJECTCLASS.lower()
                ),
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
        entry: m.Ldif.Entry,
        allowed_oids: m.Ldif.WhitelistRules | t.FrozensetMapping,
    ) -> m.Ldif.Entry:
        """Filter schema OIDs in content attributes and structured modify values.

        Returns:
            The resulting ``m.Ldif.Entry``.

        """
        allowed_value_oids = cls._extract_allowed_oids(allowed_oids)
        attrs_dict = entry.attributes_dict
        updated_attrs: t.MutableStrSequenceMapping = {
            k: list(v) for k, v in attrs_dict.items()
        }
        changed = False
        for attr_name in list(updated_attrs):
            oid_set = allowed_value_oids.get(attr_name.lower())
            if oid_set is None:
                continue
            original = updated_attrs[attr_name]
            filtered: list[str] = [
                value
                for value in original
                if (oid := cls._extract_oid_from_schema_attr(value)) is None
                or oid in oid_set
            ]
            if filtered != original:
                changed = True
            if filtered:
                updated_attrs[attr_name] = filtered
            else:
                del updated_attrs[attr_name]
        operations: list[m.Ldif.ChangeOperation] = []
        for operation in entry.change_operations:
            oid_set = allowed_value_oids.get(operation.attribute.casefold())
            if oid_set is None:
                operations.append(operation)
                continue
            values = [
                value
                for value in operation.values
                if (oid := cls._extract_oid_from_schema_attr(value.value)) is None
                or oid in oid_set
            ]
            if values == operation.values:
                operations.append(operation)
                continue
            changed = True
            if values:
                operations.append(
                    m.Ldif.ChangeOperation(
                        operation=operation.operation,
                        attribute=operation.attribute,
                        values=values,
                    ),
                )
        if not changed:
            return entry
        return m.Ldif.Entry(
            dn=entry.dn,
            attributes=(
                m.Ldif.Attributes(
                    attributes=updated_attrs,
                    attribute_metadata=entry.attributes.attribute_metadata,
                    metadata=entry.attributes.metadata,
                )
                if entry.attributes is not None
                else None
            ),
            record_kind=entry.record_kind,
            controls=entry.controls,
            changetype=entry.changetype,
            change_operations=operations,
            newrdn=entry.newrdn,
            deleteoldrdn=entry.deleteoldrdn,
            newsuperior=entry.newsuperior,
            raw_record_lines=entry.raw_record_lines,
            metadata=entry.metadata,
            validation_metadata=entry.validation_metadata,
            unique_id=entry.unique_id,
            created_at=entry.created_at,
            updated_at=entry.updated_at,
            version=entry.version,
        )


__all__: list[str] = ["FlextLdifFilters"]
