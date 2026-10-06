"""LDIF entry schema/server pattern matching utilities.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_ldif import c, p, t
from flext_ldif._models.settings import FlextLdifModelsSettings
from flext_ldif._utilities._entry_access import FlextLdifEntryAccess


class FlextLdifEntryMatching:
    """Match entries against schema markers and server pattern settings."""

    @staticmethod
    def is_schema_entry(entry: p.Ldif.Entry, *, strict: bool = True) -> bool:
        """Check if entry is a REAL schema entry with schema definitions.

        Returns:
            The resulting ``bool``.
        """
        if entry.attributes is None:
            return False
        attrs_lower = {k.lower() for k in entry.attributes.attributes}
        has_schema_attrs = bool(attrs_lower & c.Ldif.SCHEMA_CATEGORY_ATTRIBUTE_KEYS)
        dn_lower = entry.dn.value.lower() if entry.dn else ""
        has_schema_dn = any(pattern in dn_lower for pattern in c.Ldif.SCHEMA_DN_MARKERS)
        object_classes = FlextLdifEntryAccess.get_objectclass_names(entry)
        has_schema_objectclass = any(
            oc.lower() in c.Ldif.SCHEMA_OBJECTCLASS_MARKERS for oc in object_classes
        )
        if strict:
            if not has_schema_attrs:
                return False
            return has_schema_dn
        return has_schema_dn or has_schema_objectclass or has_schema_attrs

    @staticmethod
    def matches_entry_server_patterns(
        entry_dn: str,
        attributes: t.StrSequenceMapping,
        settings: FlextLdifModelsSettings.ServerPatternsConfig,
    ) -> bool:
        """Check if entry matches server-specific patterns.

        Returns:
            The resulting ``bool``.
        """
        if not entry_dn or not attributes:
            return False
        attrs = (
            dict(attributes)
            if not issubclass(attributes.__class__, dict)
            else attributes
        )
        attr_names_lower = {k.lower() for k in attrs}
        matches_dn_patterns = bool(settings.dn_patterns) and any(
            all(pattern in entry_dn for pattern in pattern_set)
            for pattern_set in settings.dn_patterns
        )
        matches_attr_prefixes = bool(settings.attr_prefixes) and any(
            attr.startswith(prefix)
            for attr in attrs
            for prefix in settings.attr_prefixes
        )
        matches_attr_names = bool(settings.attr_names) and bool(
            attr_names_lower & set(settings.attr_names),
        )
        matches_keyword_patterns = bool(settings.keyword_patterns) and any(
            keyword in attr
            for attr in attr_names_lower
            for keyword in settings.keyword_patterns
        )
        return (
            matches_dn_patterns
            or matches_attr_prefixes
            or matches_attr_names
            or matches_keyword_patterns
        )


__all__: list[str] = ["FlextLdifEntryMatching"]
