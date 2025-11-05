"""FLEXT LDIF Filters Service - Universal Entry Filtering and Categorization Engine.

╔══════════════════════════════════════════════════════════════════════════════╗
║  COMPREHENSIVE ENTRY FILTERING, CATEGORIZATION & TRANSFORMATION ENGINE      ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  ✅ DN pattern matching (wildcard/fnmatch syntax)                           ║
║  ✅ ObjectClass-based filtering with required attributes                    ║
║  ✅ Attribute presence/absence filtering                                    ║
║  ✅ Attribute and objectClass removal (entry transformation)                ║
║  ✅ Entry categorization (6-category: users/groups/hierarchy/schema/ACL)   ║
║  ✅ Schema entry detection and filtering by OID patterns                    ║
║  ✅ ACL attribute detection and extraction                                  ║
║  ✅ Exclusion metadata marking with reason tracking                         ║
║  ✅ Fluent builder pattern for complex multi-condition filtering            ║
║  ✅ Multiple API patterns (static, classmethod, builder, helpers)           ║
║  ✅ 100% server-agnostic design (works with any LDAP server)               ║
╚══════════════════════════════════════════════════════════════════════════════╝

═══════════════════════════════════════════════════════════════════════════════
REAL USAGE EXAMPLES
═══════════════════════════════════════════════════════════════════════════════

# PATTERN 1: Static Method API (Direct & Simple)
────────────────────────────────────────────────────
# Filter entries by DN pattern
result = FlextLdifFilterService.filter_by_dn(
    entries=my_entries,
    pattern="*,ou=users,dc=example,dc=com",
    mode="include"
)
filtered = result.unwrap()

# Filter by objectClass
result = FlextLdifFilterService.filter_by_objectclass(
    entries=my_entries,
    objectclass=("person", "inetOrgPerson"),
    required_attributes=["cn", "mail"]
)

# Filter by attribute presence
result = FlextLdifFilterService.filter_by_attributes(
    entries=my_entries,
    attributes=["mail"],
    match_all=False,  # Has ANY attribute
    mode="include"
)

# PATTERN 2: Classmethod for Composable/Chainable Operations
──────────────────────────────────────────────────────────────
result = (
    FlextLdifFilterService.filter(
        entries=my_entries,
        criteria="dn",
        pattern="*,ou=users,*"
    )
    .map(lambda e: e[:10])  # Take first 10
    .and_then(lambda e: FlextLdifFilterService.filter(e, criteria="objectclass", objectclass="person"))
)

# PATTERN 3: Fluent Builder Pattern
───────────────────────────────────
filtered_result = (
    FlextLdifFilterService.builder()
    .with_entries(my_entries)
    .with_dn_pattern("*,ou=users,dc=example,dc=com")
    .with_objectclass("person")
    .with_required_attributes(["cn", "mail"])
    .build()  # Returns list[Entry] directly
)

# PATTERN 4: Public Classmethod Helpers (Most Direct)
────────────────────────────────────────────────────
# Filter by DN pattern
result = FlextLdifFilterService.by_dn(entries, "*,ou=users,*")
filtered = result.unwrap()

# Filter by objectClass
result = FlextLdifFilterService.by_objectclass(
    entries, ("person", "inetOrgPerson")
)

# Filter by attributes
result = FlextLdifFilterService.by_attributes(
    entries, ["mail"], match_all=False
)

# Filter by base DN
included, excluded = FlextLdifFilterService.by_base_dn(
    entries, "dc=example,dc=com"
)

# Extract ACL entries
result = FlextLdifFilterService.extract_acl_entries(entries)

# Categorize entry
category, reason = FlextLdifFilterService.categorize(entry, rules)

# PATTERN 5: Transformation (Remove Attributes/ObjectClasses)
──────────────────────────────────────────────────────────────
# Remove temporary attributes
result = FlextLdifFilterService.remove_attributes(
    entry=my_entry,
    attributes=["tempAttribute", "debugInfo"]
)

# Remove unwanted objectClasses
result = FlextLdifFilterService.remove_objectclasses(
    entry=my_entry,
    objectclasses=["temporaryClass"]
)

# PATTERN 6: Schema & Advanced Operations
───────────────────────────────────────────
# Check if entry is schema
is_schema = FlextLdifFilterService.is_schema(entry)

# Filter schema by OID whitelist
result = FlextLdifFilterService.filter_schema_by_oids(
    entries=schema_entries,
    allowed_oids={
        "attributes": ["2.5.4.*"],
        "objectclasses": ["2.5.6.*"]
    }
)

═══════════════════════════════════════════════════════════════════════════════
QUICK REFERENCE
═══════════════════════════════════════════════════════════════════════════════

Most Common Use Cases:

# Filter entries by DN pattern
result = FlextLdifFilterService.by_dn(entries, "*,ou=users,*")
filtered = result.unwrap()

# Filter by objectClass
result = FlextLdifFilterService.by_objectclass(
    entries, ("person", "inetOrgPerson")
)

# Combine multiple conditions (builder)
filtered_result = (
    FlextLdifFilterService.builder()
    .with_entries(entries)
    .with_dn_pattern("*,ou=users,*")
    .with_objectclass("person")
    .build()
)

# Check if schema entry
is_schema = FlextLdifFilterService.is_schema(entry)

# Extract ACL entries
result = FlextLdifFilterService.extract_acl_entries(entries)
acl_entries = result.unwrap()

# Categorize entry
category, reason = FlextLdifFilterService.categorize(entry, rules)

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import fnmatch
import re
from datetime import UTC, datetime
from typing import Any

from flext_core import FlextResult, FlextService
from pydantic import Field, field_validator

from flext_ldif.constants import FlextLdifConstants
from flext_ldif.models import FlextLdifModels


class FlextLdifFilterService(FlextService[list[FlextLdifModels.Entry]]):
    """Universal LDIF Entry Filtering and Categorization Service.

    ╔══════════════════════════════════════════════════════════════════════════╗
    ║  FLEXIBLE FILTERING FOR LDIF ENTRIES: DN, OBJECTCLASS, ATTRIBUTES, ACL  ║
    ╠══════════════════════════════════════════════════════════════════════════╣
    ║  ✅ Filter entries by DN pattern (wildcard: *, ?, [seq])                ║
    ║  ✅ Filter by objectClass with required attributes                      ║
    ║  ✅ Filter by attribute presence (ANY or ALL)                           ║
    ║  ✅ Filter by base DN (hierarchy)                                       ║
    ║  ✅ Categorize entries (users, groups, hierarchy, schema, ACL, rejected)║
    ║  ✅ Schema detection and OID-based filtering                            ║
    ║  ✅ ACL attribute detection and extraction                              ║
    ║  ✅ Remove attributes/objectClasses from entries                        ║
    ║  ✅ 100% type-safe with Pydantic v2 validation                          ║
    ║  ✅ Multiple API patterns: execute(), filter(), builder(), helpers()    ║
    ╚══════════════════════════════════════════════════════════════════════════╝

    FILTER CRITERIA:
    - "dn"           Filter by DN pattern
    - "objectclass"  Filter by objectClass
    - "attributes"   Filter by attribute presence
    - "base_dn"      Filter by base DN (returns tuple)

    MODES (for all criteria):
    - "include"      Keep matching entries (default)
    - "exclude"      Remove matching entries (opposite of include)

    ATTRIBUTE MATCHING:
    - match_all=True   Entry must have ALL attributes (AND logic)
    - match_all=False  Entry must have ANY attribute (OR logic)

    """

    # ════════════════════════════════════════════════════════════════════════
    # PYDANTIC FIELDS
    # ════════════════════════════════════════════════════════════════════════

    entries: list[FlextLdifModels.Entry] = Field(
        default_factory=list,
        description="LDIF entries to filter.",
    )

    filter_criteria: str = Field(
        default="dn",
        description="Filter type: dn|objectclass|attributes|base_dn|exclude",
    )

    dn_pattern: str | None = Field(
        default=None,
        description="DN wildcard pattern for filtering.",
    )

    objectclass: str | tuple[str, ...] | None = Field(
        default=None,
        description="ObjectClass name(s) to filter by.",
    )

    required_attributes: list[str] | None = Field(
        default=None,
        description="Required attributes for objectClass filter.",
    )

    attributes: list[str] | None = Field(
        default=None,
        description="Attributes to filter by presence.",
    )

    base_dn: str | None = Field(
        default=None,
        description="Base DN for hierarchy filtering.",
    )

    mode: str = Field(
        default=FlextLdifConstants.Modes.INCLUDE,
        description="Filter mode: include|exclude",
    )

    match_all: bool = Field(
        default=False,
        description="For attribute filtering: ALL (True) or ANY (False)",
    )

    mark_excluded: bool = Field(
        default=False,
        description="Mark excluded entries in metadata (returns both matched + marked excluded). Default: False (returns only matched).",
    )

    # ════════════════════════════════════════════════════════════════════════
    # PYDANTIC VALIDATORS
    # ════════════════════════════════════════════════════════════════════════

    @field_validator("filter_criteria")
    @classmethod
    def validate_filter_criteria(cls, v: str) -> str:
        """Validate filter_criteria is valid."""
        valid = {"dn", "objectclass", "attributes", "base_dn"}
        if v not in valid:
            msg = f"Invalid filter_criteria: {v!r}. Valid: {', '.join(sorted(valid))}"
            raise ValueError(msg)
        return v

    @field_validator("mode")
    @classmethod
    def validate_mode(cls, v: str) -> str:
        """Validate mode is valid."""
        valid = {FlextLdifConstants.Modes.INCLUDE, FlextLdifConstants.Modes.EXCLUDE}
        if v not in valid:
            msg = f"Invalid mode: {v!r}. Valid: {', '.join(sorted(valid))}"
            raise ValueError(msg)
        return v

    # ════════════════════════════════════════════════════════════════════════
    # CORE EXECUTION (V2 Universal Engine)
    # ════════════════════════════════════════════════════════════════════════

    def execute(self) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Execute filtering based on filter_criteria and mode."""
        if not self.entries:
            return FlextResult[list[FlextLdifModels.Entry]].ok([])

        try:
            match self.filter_criteria:
                case "dn":
                    return self._filter_by_dn()
                case "objectclass":
                    return self._filter_by_objectclass()
                case "attributes":
                    return self._filter_by_attributes()
                case "base_dn":
                    # base_dn returns tuple, wrap in Result
                    included, _excluded = self._filter_by_base_dn()
                    return FlextResult[list[FlextLdifModels.Entry]].ok(included)
                case _:
                    return FlextResult[list[FlextLdifModels.Entry]].fail(
                        f"Unknown filter_criteria: {self.filter_criteria}"
                    )
        except Exception as e:
            return FlextResult[list[FlextLdifModels.Entry]].fail(f"Filter failed: {e}")

    # ════════════════════════════════════════════════════════════════════════
    # PUBLIC API - MINIMAL ESSENTIALS
    # ════════════════════════════════════════════════════════════════════════

    @classmethod
    def filter(
        cls,
        entries: list[FlextLdifModels.Entry],
        *,
        criteria: str = "dn",
        pattern: str | None = None,
        objectclass: str | tuple[str, ...] | None = None,
        required_attributes: list[str] | None = None,
        attributes: list[str] | None = None,
        base_dn: str | None = None,
        mode: str = FlextLdifConstants.Modes.INCLUDE,
        match_all: bool = False,
        mark_excluded: bool = False,
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Quick filter with FlextResult for composable/chainable operations.

        Args:
            entries: Entries to filter
            criteria: Filter type (dn|objectclass|attributes|base_dn)
            pattern: DN pattern (for dn criteria)
            objectclass: ObjectClass(es) (for objectclass criteria)
            required_attributes: Required attributes (for objectclass criteria)
            attributes: Attributes to filter (for attributes criteria)
            base_dn: Base DN (for base_dn criteria)
            mode: include|exclude
            match_all: For attributes: ALL or ANY
            mark_excluded: Mark excluded entries in metadata

        Returns:
            FlextResult[list[Entry]] for chaining with .map/.and_then/.unwrap

        """
        return cls(
            entries=entries,
            filter_criteria=criteria,
            dn_pattern=pattern,
            objectclass=objectclass,
            required_attributes=required_attributes,
            attributes=attributes,
            base_dn=base_dn,
            mode=mode,
            match_all=match_all,
            mark_excluded=mark_excluded,
        ).execute()

    @classmethod
    def builder(cls) -> FlextLdifFilterService:
        """Create fluent builder instance."""
        return cls(entries=[])

    def with_entries(
        self, entries: list[FlextLdifModels.Entry]
    ) -> FlextLdifFilterService:
        """Set entries to filter (fluent builder)."""
        self.entries = entries
        return self

    def with_dn_pattern(self, pattern: str) -> FlextLdifFilterService:
        """Set DN pattern filter (fluent builder)."""
        self.filter_criteria = "dn"
        self.dn_pattern = pattern
        return self

    def with_objectclass(self, *classes: str) -> FlextLdifFilterService:
        """Set objectClass filter (fluent builder)."""
        self.filter_criteria = "objectclass"
        self.objectclass = classes or None
        return self

    def with_required_attributes(self, attributes: list[str]) -> FlextLdifFilterService:
        """Set required attributes (fluent builder)."""
        self.required_attributes = attributes
        return self

    def with_attributes(self, attributes: list[str]) -> FlextLdifFilterService:
        """Set attribute filter (fluent builder)."""
        self.filter_criteria = "attributes"
        self.attributes = attributes
        return self

    def with_base_dn(self, base_dn: str) -> FlextLdifFilterService:
        """Set base DN filter (fluent builder)."""
        self.filter_criteria = "base_dn"
        self.base_dn = base_dn
        return self

    def with_mode(self, mode: str) -> FlextLdifFilterService:
        """Set filter mode: include|exclude (fluent builder)."""
        self.mode = mode
        return self

    def with_match_all(self, match_all: bool = True) -> FlextLdifFilterService:
        """Set attribute matching: ALL (True) or ANY (False) (fluent builder)."""
        self.match_all = match_all
        return self

    def exclude_matching(self) -> FlextLdifFilterService:
        """Invert filter to exclude matching entries (fluent builder)."""
        self.mode = FlextLdifConstants.Modes.EXCLUDE
        return self

    def build(self) -> list[FlextLdifModels.Entry]:
        """Execute and return unwrapped result (fluent terminal)."""
        return self.execute().unwrap()

    # ════════════════════════════════════════════════════════════════════════
    # PUBLIC CLASSMETHOD HELPERS (Direct Entry Points)
    # ════════════════════════════════════════════════════════════════════════

    @classmethod
    def by_dn(
        cls,
        entries: list[FlextLdifModels.Entry],
        pattern: str,
        mode: str = FlextLdifConstants.Modes.INCLUDE,
        mark_excluded: bool = False,
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Filter entries by DN pattern."""
        return cls(
            entries=entries,
            filter_criteria="dn",
            dn_pattern=pattern,
            mode=mode,
            mark_excluded=mark_excluded,
        ).execute()

    @classmethod
    def by_objectclass(
        cls,
        entries: list[FlextLdifModels.Entry],
        objectclass: str | tuple[str, ...],
        required_attributes: list[str] | None = None,
        mode: str = FlextLdifConstants.Modes.INCLUDE,
        mark_excluded: bool = False,
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Filter entries by objectClass."""
        return cls(
            entries=entries,
            filter_criteria="objectclass",
            objectclass=objectclass,
            required_attributes=required_attributes,
            mode=mode,
            mark_excluded=mark_excluded,
        ).execute()

    @classmethod
    def by_attributes(
        cls,
        entries: list[FlextLdifModels.Entry],
        attributes: list[str],
        match_all: bool = False,
        mode: str = FlextLdifConstants.Modes.INCLUDE,
        mark_excluded: bool = False,
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Filter entries by attribute presence."""
        return cls(
            entries=entries,
            filter_criteria="attributes",
            attributes=attributes,
            match_all=match_all,
            mode=mode,
            mark_excluded=mark_excluded,
        ).execute()

    @classmethod
    def by_base_dn(
        cls,
        entries: list[FlextLdifModels.Entry],
        base_dn: str,
        mark_excluded: bool = False,
    ) -> tuple[list[FlextLdifModels.Entry], list[FlextLdifModels.Entry]]:
        """Filter entries by base DN (hierarchy).

        Returns:
            Tuple of (included_entries, excluded_entries)

        """
        return cls(
            entries=entries,
            filter_criteria="base_dn",
            base_dn=base_dn,
            mark_excluded=mark_excluded,
        )._filter_by_base_dn()

    @classmethod
    def is_schema(cls, entry: FlextLdifModels.Entry) -> bool:
        """Check if entry is a schema entry."""
        attrs_lower = {k.lower() for k in entry.attributes.attributes}
        schema_field_names = [
            "attributetypes",
            "objectclasses",
            "matchingrules",
            "ldapsyntaxes",
        ]
        if any(sf.lower() in attrs_lower for sf in schema_field_names):
            return True

        dn_lower = entry.dn.value.lower()
        if any(
            pattern in dn_lower
            for pattern in ["cn=schema", "cn=subschema", "cn=subschemasubentry"]
        ):
            return True

        oc_values = entry.get_attribute_values(FlextLdifConstants.DictKeys.OBJECTCLASS)
        schema_classes = {"subschema", "ldapsubentry", "extensibleobject"}
        return any(
            oc.lower() in schema_classes for oc in oc_values if isinstance(oc, str)
        )

    @classmethod
    def extract_acl_entries(
        cls,
        entries: list[FlextLdifModels.Entry],
        acl_attributes: list[str] | None = None,
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Extract entries with ACL attributes."""
        filter_acl_attrs = acl_attributes or ["acl", "aci", "olcAccess"]

        # Exclude schema entries first
        non_schema_entries = [e for e in entries if not cls.is_schema(e)]

        return cls.by_attributes(
            non_schema_entries,
            filter_acl_attrs,
            match_all=False,
            mode=FlextLdifConstants.Modes.INCLUDE,
            mark_excluded=False,
        )

    @classmethod
    def remove_attributes(
        cls,
        entry: FlextLdifModels.Entry,
        attributes: list[str],
    ) -> FlextResult[FlextLdifModels.Entry]:
        """Remove attributes from entry."""
        try:
            blocked_lower = {attr.lower() for attr in attributes}
            filtered_attrs_dict = {
                key: value
                for key, value in entry.attributes.attributes.items()
                if key.lower() not in blocked_lower
            }

            new_attributes = FlextLdifModels.LdifAttributes(
                attributes=filtered_attrs_dict,
                metadata=entry.attributes.metadata,
            )

            # Entry.create() already returns FlextResult, return directly
            return FlextLdifModels.Entry.create(
                dn=entry.dn,
                attributes=new_attributes,
            )
        except Exception as e:
            return FlextResult[FlextLdifModels.Entry].fail(
                f"Failed to remove attributes: {e}"
            )

    @classmethod
    def remove_objectclasses(
        cls,
        entry: FlextLdifModels.Entry,
        objectclasses: list[str],
    ) -> FlextResult[FlextLdifModels.Entry]:
        """Remove objectClasses from entry."""
        try:
            blocked_lower = {oc.lower() for oc in objectclasses}

            oc_values = entry.get_attribute_values(
                FlextLdifConstants.DictKeys.OBJECTCLASS
            )
            if not oc_values:
                return FlextResult[FlextLdifModels.Entry].ok(entry)

            filtered_ocs = [oc for oc in oc_values if oc.lower() not in blocked_lower]
            if not filtered_ocs:
                return FlextResult[FlextLdifModels.Entry].fail(
                    "All objectClasses would be removed"
                )

            new_attrs_dict = dict(entry.attributes.attributes)
            new_attrs_dict[FlextLdifConstants.DictKeys.OBJECTCLASS] = filtered_ocs

            new_attributes = FlextLdifModels.LdifAttributes(
                attributes=new_attrs_dict,
                metadata=entry.attributes.metadata,
            )

            # Entry.create() already returns FlextResult, return directly
            return FlextLdifModels.Entry.create(
                dn=entry.dn,
                attributes=new_attributes,
            )
        except Exception as e:
            return FlextResult[FlextLdifModels.Entry].fail(
                f"Failed to remove objectClasses: {e}"
            )

    @classmethod
    def categorize(
        cls,
        entry: FlextLdifModels.Entry,
        rules: dict[str, Any],
    ) -> tuple[str, str | None]:
        """Categorize entry into 6 categories.

        Categories (in priority order):
        - schema: Has attributeTypes/objectClasses
        - hierarchy: Containers (organizationalUnit, etc)
        - users: User accounts
        - groups: Group entries
        - acl: Entries with ACL attributes
        - rejected: No match

        Returns:
            Tuple of (category, rejection_reason)

        """
        # Check schema first
        if cls.is_schema(entry):
            return ("schema", None)

        # Parse rules
        hierarchy_classes = tuple(rules.get("hierarchy_objectclasses", []))
        user_classes = tuple(rules.get("user_objectclasses", []))
        group_classes = tuple(rules.get("group_objectclasses", []))
        acl_attributes = rules.get("acl_attributes", ["acl", "aci", "olcAccess"])

        # Check objectClass hierarchy BEFORE ACL (important!)
        if hierarchy_classes and cls._has_objectclass(entry, hierarchy_classes):
            return ("hierarchy", None)

        # Check users
        if user_classes and cls._has_objectclass(entry, user_classes):
            return ("users", None)

        # Check groups
        if group_classes and cls._has_objectclass(entry, group_classes):
            return ("groups", None)

        # Check ACL
        if cls._has_attributes(entry, acl_attributes, match_any=True):
            return ("acl", None)

        # Rejected
        return ("rejected", "No category match")

    @classmethod
    def filter_schema_by_oids(
        cls,
        entries: list[FlextLdifModels.Entry],
        allowed_oids: dict[str, list[str]],
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Filter schema entries by allowed OID patterns.

        Args:
        entries: Schema entries to filter
        allowed_oids: Dict with keys:
            - "attributes": OID patterns for attributeTypes
            - "objectclasses": OID patterns for objectClasses

        Returns:
        FlextResult with filtered entries

        """
        if not entries or not allowed_oids:
            return FlextResult[list[FlextLdifModels.Entry]].ok(entries)

        allowed_attr_oids = allowed_oids.get("attributes", [])
        allowed_oc_oids = allowed_oids.get("objectclasses", [])

        filtered = []
        for entry in entries:
            attrs = dict(entry.attributes.attributes)
            keep_entry = False

            # Check attributeTypes
            for key in ["attributeTypes", "attributetypes"]:
                if key in attrs:
                    values = attrs[key]
                    if isinstance(values, list):
                        for val in values:
                            oid_match = re.search(r"\(\s*(\d+(?:\.\d+)*)", str(val))
                            if oid_match and fnmatch.fnmatch(
                                oid_match.group(1),
                                "|".join(allowed_attr_oids)
                                if allowed_attr_oids
                                else "*",
                            ):
                                keep_entry = True
                                break

            # Check objectClasses
            for key in ["objectClasses", "objectclasses"]:
                if key in attrs:
                    values = attrs[key]
                    if isinstance(values, list):
                        for val in values:
                            oid_match = re.search(r"\(\s*(\d+(?:\.\d+)*)", str(val))
                            if oid_match and fnmatch.fnmatch(
                                oid_match.group(1),
                                "|".join(allowed_oc_oids) if allowed_oc_oids else "*",
                            ):
                                keep_entry = True
                                break

            if keep_entry:
                filtered.append(entry)

        return FlextResult[list[FlextLdifModels.Entry]].ok(filtered)

    # ════════════════════════════════════════════════════════════════════════
    # PRIVATE IMPLEMENTATION (DRY Core)
    # ════════════════════════════════════════════════════════════════════════

    def _filter_by_dn(self) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Filter by DN pattern."""
        try:
            if not self.dn_pattern:
                return FlextResult[list[FlextLdifModels.Entry]].fail(
                    "dn_pattern required for dn filter"
                )

            pattern = self.dn_pattern  # Type narrowing: str
            filtered = []
            for entry in self.entries:
                matches = fnmatch.fnmatch(entry.dn.value.lower(), pattern.lower())
                include = (
                    self.mode == FlextLdifConstants.Modes.INCLUDE and matches
                ) or (self.mode == FlextLdifConstants.Modes.EXCLUDE and not matches)

                if include:
                    filtered.append(entry)
                elif self.mark_excluded:
                    filtered.append(
                        self._mark_excluded(entry, f"DN pattern: {self.dn_pattern}")
                    )

            return FlextResult[list[FlextLdifModels.Entry]].ok(filtered)
        except Exception as e:
            return FlextResult[list[FlextLdifModels.Entry]].fail(
                f"DN filter failed: {e}"
            )

    def _filter_by_objectclass(self) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Filter by objectClass."""
        try:
            if not self.objectclass:
                return FlextResult[list[FlextLdifModels.Entry]].fail(
                    "objectclass required"
                )

            oc_tuple = (
                self.objectclass
                if isinstance(self.objectclass, tuple)
                else (self.objectclass,)
            )

            filtered = []
            for entry in self.entries:
                has_oc = self._has_objectclass(entry, oc_tuple)
                has_attrs = True

                if has_oc and self.required_attributes:
                    has_attrs = self._has_attributes(
                        entry, self.required_attributes, match_any=False
                    )

                matches = has_oc and has_attrs
                include = (
                    self.mode == FlextLdifConstants.Modes.INCLUDE and matches
                ) or (self.mode == FlextLdifConstants.Modes.EXCLUDE and not matches)

                if include:
                    filtered.append(entry)
                elif self.mark_excluded:
                    filtered.append(
                        self._mark_excluded(entry, f"ObjectClass filter: {oc_tuple}")
                    )

            return FlextResult[list[FlextLdifModels.Entry]].ok(filtered)
        except Exception as e:
            return FlextResult[list[FlextLdifModels.Entry]].fail(
                f"ObjectClass filter failed: {e}"
            )

    def _filter_by_attributes(self) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Filter by attribute presence."""
        try:
            if not self.attributes:
                return FlextResult[list[FlextLdifModels.Entry]].fail(
                    "attributes required"
                )

            attrs = self.attributes  # Type narrowing: list[str]
            filtered = []
            for entry in self.entries:
                matches = self._has_attributes(
                    entry, attrs, match_any=not self.match_all
                )
                include = (
                    self.mode == FlextLdifConstants.Modes.INCLUDE and matches
                ) or (self.mode == FlextLdifConstants.Modes.EXCLUDE and not matches)

                if include:
                    filtered.append(entry)
                elif self.mark_excluded:
                    filtered.append(
                        self._mark_excluded(
                            entry, f"Attribute filter: {self.attributes}"
                        )
                    )

            return FlextResult[list[FlextLdifModels.Entry]].ok(filtered)
        except Exception as e:
            return FlextResult[list[FlextLdifModels.Entry]].fail(
                f"Attribute filter failed: {e}"
            )

    def _filter_by_base_dn(
        self,
    ) -> tuple[list[FlextLdifModels.Entry], list[FlextLdifModels.Entry]]:
        """Filter by base DN."""
        if not self.base_dn:
            return (self.entries, [])

        base_dn_lower = self.base_dn.lower().strip()
        included = []
        excluded = []

        for entry in self.entries:
            entry_dn_lower = entry.dn.value.lower().strip()

            if entry_dn_lower == base_dn_lower or entry_dn_lower.endswith(
                f",{base_dn_lower}"
            ):
                included.append(entry)
            elif self.mark_excluded:
                excluded.append(self._mark_excluded(entry, f"Base DN: {self.base_dn}"))
            else:
                excluded.append(entry)

        return (included, excluded)

    def _apply_exclude_filter(self) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Apply invert/exclude filter logic."""
        try:
            # Store original mode and invert
            original_mode = self.mode
            self.mode = (
                FlextLdifConstants.Modes.EXCLUDE
                if original_mode == FlextLdifConstants.Modes.INCLUDE
                else FlextLdifConstants.Modes.INCLUDE
            )

            # Apply the appropriate filter
            match self.filter_criteria:
                case "dn":
                    result = self._filter_by_dn()
                case "objectclass":
                    result = self._filter_by_objectclass()
                case "attributes":
                    result = self._filter_by_attributes()
                case _:
                    result = FlextResult[list[FlextLdifModels.Entry]].fail(
                        f"Cannot exclude with criteria: {self.filter_criteria}"
                    )

            # Restore original mode
            self.mode = original_mode
            return result
        except Exception as e:
            return FlextResult[list[FlextLdifModels.Entry]].fail(f"Exclude failed: {e}")

    @staticmethod
    def _has_objectclass(
        entry: FlextLdifModels.Entry, objectclasses: tuple[str, ...]
    ) -> bool:
        """Check if entry has any of the objectClasses."""
        entry_classes = entry.get_attribute_values(
            FlextLdifConstants.DictKeys.OBJECTCLASS
        )
        if not entry_classes:
            return False

        entry_classes_lower = [cls.lower() for cls in entry_classes]
        objectclasses_lower = [cls.lower() for cls in objectclasses]

        return any(cls in entry_classes_lower for cls in objectclasses_lower)

    @staticmethod
    def _has_attributes(
        entry: FlextLdifModels.Entry, attributes: list[str], match_any: bool = True
    ) -> bool:
        """Check if entry has attributes (ANY or ALL)."""
        if match_any:
            return any(entry.has_attribute(attr) for attr in attributes)
        return all(entry.has_attribute(attr) for attr in attributes)

    @staticmethod
    def _mark_excluded(
        entry: FlextLdifModels.Entry, reason: str
    ) -> FlextLdifModels.Entry:
        """Mark entry as excluded."""
        exclusion_info = FlextLdifModels.ExclusionInfo(
            excluded=True,
            exclusion_reason=reason,
            timestamp=datetime.now(UTC).isoformat(),
        )

        if entry.metadata is None:
            new_metadata = FlextLdifModels.QuirkMetadata(
                extensions={"exclusion_info": exclusion_info.model_dump()},
            )
        else:
            new_extensions = {**entry.metadata.extensions}
            new_extensions["exclusion_info"] = exclusion_info.model_dump()
            new_metadata = FlextLdifModels.QuirkMetadata(
                original_format=entry.metadata.original_format,
                quirk_type=entry.metadata.quirk_type,
                parsed_timestamp=entry.metadata.parsed_timestamp,
                extensions=new_extensions,
                custom_data=entry.metadata.custom_data,
            )

        return entry.model_copy(update={"metadata": new_metadata})


class FlextLdifFilters:
    """Static utility class for entry exclusion management and DN pattern matching.

    This class provides methods for:
    - Checking if entries are marked as excluded
    - Retrieving exclusion reasons
    - DN pattern matching with wildcard support
    - ACL attribute detection
    """

    @staticmethod
    def is_entry_excluded(entry: FlextLdifModels.Entry) -> bool:
        """Check if entry is marked as excluded in metadata.

        Args:
            entry: The entry to check

        Returns:
            True if entry is marked as excluded, False otherwise

        """
        if entry.metadata is None:
            return False

        exclusion_info = entry.metadata.extensions.get("exclusion_info")
        if not isinstance(exclusion_info, dict):
            return False

        excluded = exclusion_info.get("excluded")
        return isinstance(excluded, bool) and excluded

    @staticmethod
    def get_exclusion_reason(entry: FlextLdifModels.Entry) -> str | None:
        """Get exclusion reason from entry metadata.

        Args:
            entry: The entry to check

        Returns:
            Exclusion reason string, or None if not excluded

        """
        if entry.metadata is None:
            return None

        exclusion_info = entry.metadata.extensions.get("exclusion_info")
        if not isinstance(exclusion_info, dict):
            return None

        # Only return reason if entry is actually marked as excluded
        if not FlextLdifFilters.is_entry_excluded(entry):
            return None

        reason = exclusion_info.get("exclusion_reason")
        return reason if isinstance(reason, str) else None

    @staticmethod
    def _matches_dn_pattern(dn: str, patterns: list[str]) -> bool:
        """Check if DN matches any of the regex patterns.

        Args:
            dn: The DN to match
            patterns: List of regex patterns

        Returns:
            True if DN matches any pattern, False otherwise

        Raises:
            ValueError: If any pattern is invalid regex

        """
        if not patterns:
            return False

        # First validate ALL patterns before matching
        invalid_patterns = []
        for pattern in patterns:
            try:
                re.compile(pattern)
            except re.error:
                invalid_patterns.append(pattern)

        if invalid_patterns:
            msg = f"Invalid regex patterns: {invalid_patterns}"
            raise ValueError(msg)

        # Now do the matching
        dn_lower = dn.lower()
        for pattern in patterns:
            try:
                pattern_lower = pattern.lower()
                if re.search(pattern_lower, dn_lower):
                    return True
            except re.error:
                # This shouldn't happen since we already validated,
                # but skip if it does
                continue

        return False

    @staticmethod
    def _has_acl_attributes(
        entry: FlextLdifModels.Entry, attributes: list[str]
    ) -> bool:
        """Check if entry has any of the specified ACL attributes.

        Args:
            entry: The entry to check
            attributes: List of attribute names to check for

        Returns:
            True if entry has any of the attributes, False otherwise

        """
        if not attributes:
            return False

        entry_attrs_lower = {attr.lower() for attr in entry.attributes}
        return any(attr.lower() in entry_attrs_lower for attr in attributes)

    @staticmethod
    def categorize_entry(
        entry: FlextLdifModels.Entry,
        rules: dict[str, Any],
        whitelist_rules: dict[str, Any] | None = None,
    ) -> tuple[str, str | None]:
        """Categorize entry into 6 categories.

        Delegates to FlextLdifFilterService.categorize, with optional whitelist validation.

        Args:
            entry: The entry to categorize
            rules: Rules dictionary with category configuration
            whitelist_rules: Optional whitelist rules (e.g., blocked_objectclasses)

        Returns:
            Tuple of (category, rejection_reason)

        """
        # Check for blocked objectClasses first
        if whitelist_rules:
            blocked_ocs = whitelist_rules.get("blocked_objectclasses", [])
            if blocked_ocs:
                entry_ocs = entry.get_attribute_values("objectClass")
                if entry_ocs:
                    blocked_ocs_lower = {oc.lower() for oc in blocked_ocs}
                    for oc in entry_ocs:
                        if oc.lower() in blocked_ocs_lower:
                            return ("rejected", f"Blocked objectClass: {oc}")

        # Delegate to FilterService for main categorization
        category, reason = FlextLdifFilterService.categorize(entry, rules)

        # Check DN patterns for category-specific matching
        if category == "users":
            user_dn_patterns = rules.get("user_dn_patterns", [])
            if user_dn_patterns:
                try:
                    if not FlextLdifFilters._matches_dn_pattern(
                        entry.dn.value, user_dn_patterns
                    ):
                        return ("rejected", "DN pattern does not match user rules")
                except ValueError:
                    # Invalid patterns - just let it through
                    pass

        if category == "groups":
            group_dn_patterns = rules.get("group_dn_patterns", [])
            if group_dn_patterns:
                try:
                    if not FlextLdifFilters._matches_dn_pattern(
                        entry.dn.value, group_dn_patterns
                    ):
                        return ("rejected", "DN pattern does not match group rules")
                except ValueError:
                    # Invalid patterns - just let it through
                    pass

        return (category, reason)

    @staticmethod
    def filter_entries_by_dn(
        entries: list[FlextLdifModels.Entry],
        pattern: str,
        mode: str = "include",
        mark_excluded: bool = False,
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Filter entries by DN pattern.

        Args:
            entries: List of entries to filter
            pattern: DN wildcard pattern
            mode: "include" or "exclude"
            mark_excluded: Whether to mark excluded entries

        Returns:
            FlextResult with filtered entries

        """
        filter_service = FlextLdifFilterService(
            entries=entries,
            dn_pattern=pattern,
            filter_criteria="dn",
            mode=mode,
            mark_excluded=mark_excluded,
        )
        return filter_service.execute()

    @staticmethod
    def filter_entries_by_objectclass(
        entries: list[FlextLdifModels.Entry],
        objectclass: str | tuple[str, ...],
        required_attributes: list[str] | None = None,
        mode: str = "include",
        mark_excluded: bool = False,
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Filter entries by objectClass.

        Args:
            entries: List of entries to filter
            objectclass: ObjectClass name(s)
            required_attributes: Required attributes for match
            mode: "include" or "exclude"
            mark_excluded: Whether to mark excluded entries

        Returns:
            FlextResult with filtered entries

        """
        filter_service = FlextLdifFilterService(
            entries=entries,
            objectclass=objectclass,
            required_attributes=required_attributes,
            filter_criteria="objectclass",
            mode=mode,
            mark_excluded=mark_excluded,
        )
        return filter_service.execute()

    @staticmethod
    def filter_entries_by_attributes(
        entries: list[FlextLdifModels.Entry],
        attributes: list[str],
        match_all: bool = False,
        mode: str = "include",
        mark_excluded: bool = False,
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Filter entries by attribute presence.

        Args:
            entries: List of entries to filter
            attributes: Attribute names to check
            match_all: Match ALL attributes (vs ANY)
            mode: "include" or "exclude"
            mark_excluded: Whether to mark excluded entries

        Returns:
            FlextResult with filtered entries

        """
        filter_service = FlextLdifFilterService(
            entries=entries,
            attributes=attributes,
            match_all=match_all,
            filter_criteria="attributes",
            mode=mode,
            mark_excluded=mark_excluded,
        )
        return filter_service.execute()

    @staticmethod
    def filter_entry_attributes(
        entry: FlextLdifModels.Entry,
        attributes_to_remove: list[str],
    ) -> FlextResult[FlextLdifModels.Entry]:
        """Remove specified attributes from entry.

        Args:
            entry: The entry to modify
            attributes_to_remove: Attribute names to remove

        Returns:
            FlextResult with modified entry

        """
        try:
            if not attributes_to_remove:
                return FlextResult[FlextLdifModels.Entry].ok(entry)

            # Create filtered attributes dict
            attrs_lower = {attr.lower() for attr in attributes_to_remove}

            filtered_attrs = {
                key: values
                for key, values in entry.attributes.items()
                if key.lower() not in attrs_lower
            }

            # Create new LdifAttributes
            attrs_result = FlextLdifModels.LdifAttributes.create(filtered_attrs)
            if not attrs_result.is_success:
                return FlextResult[FlextLdifModels.Entry].fail(attrs_result.error)

            new_entry = entry.model_copy(update={"attributes": attrs_result.unwrap()})
            return FlextResult[FlextLdifModels.Entry].ok(new_entry)

        except Exception as e:
            return FlextResult[FlextLdifModels.Entry].fail(
                f"Filter attributes failed: {e}"
            )

    @staticmethod
    def filter_entry_objectclasses(
        entry: FlextLdifModels.Entry,
        objectclasses_to_remove: list[str],
    ) -> FlextResult[FlextLdifModels.Entry]:
        """Remove specified objectClasses from entry.

        Args:
            entry: The entry to modify
            objectclasses_to_remove: ObjectClass names to remove

        Returns:
            FlextResult with modified entry

        """
        try:
            oc_to_remove_lower = {oc.lower() for oc in objectclasses_to_remove}
            current_ocs = entry.get_attribute_values("objectClass")

            if not current_ocs:
                return FlextResult[FlextLdifModels.Entry].ok(entry)

            # Filter objectClasses
            filtered_ocs = [
                oc for oc in current_ocs if oc.lower() not in oc_to_remove_lower
            ]

            # Check if all objectClasses would be removed
            if not filtered_ocs:
                return FlextResult[FlextLdifModels.Entry].fail(
                    "All objectClasses would be removed"
                )

            # Create filtered attributes dict
            filtered_attrs = dict(entry.attributes.attributes)
            filtered_attrs["objectClass"] = filtered_ocs

            # Create new LdifAttributes
            attrs_result = FlextLdifModels.LdifAttributes.create(filtered_attrs)
            if not attrs_result.is_success:
                return FlextResult[FlextLdifModels.Entry].fail(attrs_result.error)

            new_entry = entry.model_copy(update={"attributes": attrs_result.unwrap()})
            return FlextResult[FlextLdifModels.Entry].ok(new_entry)

        except Exception as e:
            return FlextResult[FlextLdifModels.Entry].fail(
                f"Filter objectClasses failed: {e}"
            )


__all__ = ["FlextLdifFilterService", "FlextLdifFilters"]
