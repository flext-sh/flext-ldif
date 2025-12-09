"""Detection and Identification Mixins for LDIF Server Quirks.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

This module provides reusable mixins that consolidate common detection logic
across all 12 server implementations. Eliminates ~900-1,200 lines of duplication
by extracting can_handle_* patterns into shared mixin classes.

Works with ANY data type sent to detection methods:
- String definitions (raw LDIF format)
- Model objects (Pydantic models)
- List/set/tuple of objectClasses
- Raw ACL lines
- Any nested structure

Usage in Schema:
    class CustomSchema(FlextLdifServersRfc.Schema, FlextLdifUtilities.Detection.OidPatternMixin):
        def can_handle_attribute(self, attr_def):
            # Handles: str | SchemaAttribute
            return self.can_handle_oid_pattern(
                attr_def,
                FlextLdifServersCustom.Constants.DETECTION_OID_PATTERN
            )

Usage in ACL:
    class CustomAcl(FlextLdifServersRfc.Acl, FlextLdifUtilities.Detection.AclDetectionMixin):
        def can_handle_acl(self, acl_line):
            # Handles: str | Acl
            return self.can_handle_acl_attribute(
                acl_line,
                FlextLdifServersCustom.Constants.ACL_ATTRIBUTE_NAME
            )

Usage in Entry:
    class CustomEntry(FlextLdifServersRfc.Entry, FlextLdifUtilities.Detection.ObjectClassDetectionMixin):
        def can_handle(self, entry_dn, attributes):
            # Handles: str DN + dict attributes
            return self.can_handle_objectclass_in_entry(
                attributes.get('objectClass'),
                FlextLdifServersCustom.Constants.DETECTION_OBJECTCLASS_NAMES
            )
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence

from flext_core import FlextRuntime

from flext_ldif.models import m
from flext_ldif.protocols import p


class FlextLdifUtilitiesDetection:
    """Detection utilities for LDIF server quirks."""

    class BaseDetectionMixin:
        """Base mixin with shared _get_constants method.

        Eliminates duplications of _get_constants across all detection mixins.
        """

        def _get_constants(
            self,
            required_attr: str | None = None,
        ) -> type[p.Ldif.Constants.ServerConstantsProtocol] | None:
            """Get Constants class from server class via MRO traversal.

            Args:
                required_attr: Optional attribute name that Constants must have

            Returns:
                Constants class from parent server class, or None if not found

            """
            # Traverse MRO to find the server class that has Constants
            for cls in self.__class__.__mro__:
                # Look for server classes (FlextLdifServers*) with Constants
                if (
                    cls.__name__.startswith("FlextLdifServers")
                    and hasattr(cls, "Constants")
                    and not FlextRuntime.is_dict_like(getattr(cls, "Constants", None))
                ):
                    constants_class: type = cls.Constants
                    # Verify protocol compliance at runtime using runtime_checkable
                    # Protocol compliance is structural - verified via hasattr checks
                    if required_attr is None:
                        # Check all protocol attributes exist (structural compliance)
                        if all(
                            hasattr(constants_class, attr)
                            for attr in (
                                "DETECTION_OID_PATTERN",
                                "DETECTION_ATTRIBUTE_PREFIXES",
                                "DETECTION_OBJECTCLASS_NAMES",
                                "DETECTION_DN_MARKERS",
                                "ACL_ATTRIBUTE_NAME",
                            )
                        ):
                            return constants_class
                    elif hasattr(constants_class, required_attr):
                        # Required attribute exists - return Constants class
                        return constants_class
            return None

    class PatternDetectionMixin(BaseDetectionMixin):
        """Mixin for regex pattern matching across different data types.

        Core utility for matching patterns in:
        - Raw string definitions
        - Model OID fields
        - Attribute names
        - DN patterns
        """

        @staticmethod
        def can_handle_pattern(
            pattern: str,
            *,
            data: (
                str
                | p.Ldif.Models.SchemaAttributeProtocol
                | p.Ldif.Models.SchemaObjectClassProtocol
                | p.Ldif.Models.EntryProtocol
                | p.Ldif.Models.AclProtocol
                | None
            ),
        ) -> bool:
            """Check if data matches regex pattern.

            Handles:
            - str: Direct pattern match
            - obj with .oid: Match against oid field
            - obj with .name: Match against name field
            - Other types: Convert to string and match

            Args:
                pattern: Regex pattern to match
                data: Data to check (str, model, or primitive type)

            Returns:
                True if data matches pattern

            """
            try:
                # String: direct match
                if isinstance(data, str):
                    return bool(re.search(pattern, data))

                # Model with oid field (attributes, objectClasses)
                oid = getattr(data, "oid", None)
                if oid:
                    return bool(re.search(pattern, str(oid)))

                # Model with name field
                name = getattr(data, "name", None)
                if name:
                    return bool(re.search(pattern, str(name)))

                # Try to convert to string
                if data is not None:
                    return bool(re.search(pattern, str(data)))

                return False
            except (re.error, TypeError, AttributeError):
                return False

        @staticmethod
        def can_handle_prefix(
            data: (
                str
                | p.Ldif.Models.SchemaAttributeProtocol
                | p.Ldif.Models.SchemaObjectClassProtocol
                | p.Ldif.Models.EntryProtocol
                | p.Ldif.Models.AclProtocol
                | None
            ),
            prefixes: frozenset[str],
        ) -> bool:
            """Check if data starts with any prefix (case-insensitive).

            Handles:
            - str: Direct prefix match
            - obj with .name: Match against name field
            - obj with .oid: Extract name from OID definition
            - Any other type: Convert to string

            Args:
                data: Data to check
                prefixes: Frozenset of prefixes to match

            Returns:
                True if data starts with any prefix (case-insensitive)

            """
            # String: direct match
            if isinstance(data, str):
                data_lower = data.lower()
                return any(data_lower.startswith(p.lower()) for p in prefixes)

            # Model with name field
            name = getattr(data, "name", None)
            if name:
                name_lower = str(name).lower()
                return any(name_lower.startswith(p.lower()) for p in prefixes)

            # Try converting to string
            try:
                if data is not None:
                    data_str = str(data).lower()
                    return any(data_str.startswith(p.lower()) for p in prefixes)
            except (TypeError, AttributeError):
                pass

            return False

        @staticmethod
        def can_handle_in_set(
            data: (str | m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass | None),
            items: frozenset[str],
        ) -> bool:
            """Check if data is in set (case-insensitive).

            Handles:
            - str: Direct set membership
            - obj with .name: Check name in set
            - Any other type: Convert to string

            Args:
                data: Data to check
                items: Frozenset of items

            Returns:
                True if data is in set (case-insensitive)

            """
            # String: direct match
            if isinstance(data, str):
                items_lower = {item.lower() for item in items}
                return data.lower() in items_lower

            # Model with name field
            name = getattr(data, "name", None)
            if name:
                items_lower = {item.lower() for item in items}
                return str(name).lower() in items_lower

            # Try converting to string
            try:
                if data is not None:
                    items_lower = {item.lower() for item in items}
                    return str(data).lower() in items_lower
            except (TypeError, AttributeError):
                pass

            return False

    class OidPatternMixin(PatternDetectionMixin):
        """Mixin for OID-based pattern detection in Schema.

        Consolidates can_handle_attribute() and can_handle_objectclass() logic
        across all servers that detect by OID pattern (e.g., 2.16.840.1.113894.*).

        Works with:
        - Raw attribute/objectClass definition strings
        - SchemaAttribute/SchemaObjectClass models
        - Any data type sent to detection methods
        """

        def _can_handle_schema_item_by_pattern(
            self,
            schema_item: (
                str | p.Ldif.Models.SchemaAttributeProtocol | p.Ldif.Models.SchemaObjectClassProtocol
            ),
        ) -> bool:
            """Generic method to check if schema item matches OID detection pattern.

            Consolidated logic for both attributes and objectClasses.
            Override in subclass and set DETECTION_OID_PATTERN constant.

            Args:
                schema_item: Schema definition (attribute or objectClass, string or model)

            Returns:
                True if schema item OID matches pattern, True if no pattern (match all)

            """
            # Get pattern from Constants class
            constants = self._get_constants()
            if constants is None:
                return True  # No Constants class or pattern = match all
            pattern = getattr(constants, "DETECTION_OID_PATTERN", None)
            if not pattern:
                return True  # No pattern = match all
            # can_handle_pattern accepts object and handles conversion internally
            return self.can_handle_pattern(pattern, data=schema_item)

        def can_handle_attribute(
            self,
            attr_definition: str | p.Ldif.Models.SchemaAttributeProtocol,
        ) -> bool:
            """Check if attribute matches OID detection pattern.

            Delegates to generic schema item handler.

            Args:
                attr_definition: Attribute definition (string or model)

            Returns:
                True if attribute OID matches pattern

            """
            return self._can_handle_schema_item_by_pattern(attr_definition)

        def can_handle_objectclass(
            self,
            oc_definition: str | p.Ldif.Models.SchemaObjectClassProtocol,
        ) -> bool:
            """Check if objectClass matches OID detection pattern.

            Delegates to generic schema item handler.

            Args:
                oc_definition: ObjectClass definition (string or model)

            Returns:
                True if objectClass OID matches pattern

            """
            return self._can_handle_schema_item_by_pattern(oc_definition)

    class PrefixDetectionMixin(PatternDetectionMixin):
        """Mixin for attribute name prefix-based detection in Schema.

        Consolidates can_handle_attribute() logic for servers detected by
        attribute name prefixes (e.g., "orcl*" for Oracle OID, "ds-*" for DS).

        Works with:
        - Raw attribute definition strings
        - SchemaAttribute models
        - Any data type sent to detection methods
        """

        def can_handle_attribute(
            self,
            attr_definition: str | m.Ldif.SchemaAttribute,
        ) -> bool:
            """Check if attribute name matches detection prefixes.

            Override in subclass and set DETECTION_ATTRIBUTE_PREFIXES constant.

            Args:
                attr_definition: Attribute definition (string or model)

            Returns:
                True if attribute name starts with any detection prefix

            """
            # Get prefixes from Constants class
            constants = self._get_constants()
            if constants is None:
                return True  # No Constants class or prefixes = match all
            prefixes = getattr(constants, "DETECTION_ATTRIBUTE_PREFIXES", None)
            if not prefixes:
                return True  # No prefixes = match all
            return self.can_handle_prefix(attr_definition, prefixes)

    class ObjectClassDetectionMixin(PatternDetectionMixin):
        """Mixin for objectClass name-based detection in Entry.

        Consolidates can_handle() logic for servers detected by objectClass names
        (e.g., "orcldirectory" for Oracle OID, "olcConfig" for OpenLDAP).

        Works with:
        - Entry DN (string)
        - Entry attributes (dict with objectClass key)
        - Any combination of attribute values
        """

        def can_handle(
            self,
            _entry_dn: str,
            attributes: (
                Mapping[str, Sequence[str] | str]
                | dict[str, Sequence[str] | str]
                | m.Ldif.Entry
            ),
        ) -> bool:
            """Check if entry objectClasses match detection list.

            Override in subclass and set DETECTION_OBJECTCLASS_NAMES constant.

            Args:
                _entry_dn: Entry distinguished name (unused in base implementation)
                attributes: Entry attributes dict with 'objectClass' key

            Returns:
                True if any entry objectClass is in detection list

            """
            if not attributes:
                return False

            # Get detection classes from Constants class
            constants = self._get_constants()
            if constants is None:
                return True  # No Constants class or detection classes = match all
            detection_classes = getattr(constants, "DETECTION_OBJECTCLASS_NAMES", None)
            if not detection_classes:
                return True  # No detection classes = match all

            # Get objectClass from attributes
            objectclasses: Sequence[str] | str | None = None
            # Check for EntryProtocol first (has get_objectclass_names method)
            if isinstance(attributes, p.Ldif.Models.EntryProtocol):
                # Entry protocol has get_objectclass_names method
                objectclasses = list(attributes.get_objectclass_names())
            elif isinstance(attributes, Mapping):
                obj_class = attributes.get("objectClass") or attributes.get(
                    "objectclass",
                )
                if obj_class is not None:
                    objectclasses = obj_class

            if not objectclasses:
                return False

            # Handle list/set/tuple of objectClasses
            if isinstance(objectclasses, (list, tuple, set)):
                detection_set = {oc.lower() for oc in detection_classes}
                oc_set = {str(oc).lower() for oc in objectclasses}
                return bool(oc_set & detection_set)

            # Handle single objectClass string
            if isinstance(objectclasses, str):
                return self.can_handle_in_set(objectclasses, detection_classes)

            return False

    class DnMarkerMixin(PatternDetectionMixin):
        """Mixin for DN pattern-based detection in Entry.

        Consolidates can_handle() logic for servers detected by DN patterns
        (e.g., "cn=config" for OpenLDAP, "cn=orcl*" for Oracle OID).

        Works with:
        - Entry DN (string)
        - Entry attributes (dict) - DN check is independent
        """

        def can_handle(
            self,
            entry_dn: str,
            _attributes: (
                Mapping[str, Sequence[str] | str]
                | dict[str, Sequence[str] | str]
                | m.Ldif.Entry
                | None
            ),
        ) -> bool:
            """Check if entry DN matches detection markers.

            Override in subclass and set DETECTION_DN_MARKERS constant.

            Args:
                entry_dn: Entry distinguished name
                _attributes: Entry attributes (unused in base implementation)

            Returns:
                True if DN contains any detection marker

            """
            # Get DN markers from Constants class
            constants = self._get_constants()
            if constants is None:
                return True  # No Constants class or markers = match all
            markers = getattr(constants, "DETECTION_DN_MARKERS", None)
            if not markers:
                return True  # No markers = match all

            if not entry_dn:
                return False

            dn_lower = entry_dn.lower()
            return any(marker.lower() in dn_lower for marker in markers)

    class AclDetectionMixin(PatternDetectionMixin):
        """Mixin for ACL attribute-based detection in ACL.

        Consolidates can_handle_acl() logic for servers with ACL attribute
        detection (e.g., "orclaci" for Oracle OID, "aci" for RFC/OUD).

        Works with:
        - Raw ACL lines (strings)
        - ACL models
        - Any data type sent to detection methods
        """

        def can_handle_acl(
            self,
            acl_line: str | p.Ldif.Models.AclProtocol,
        ) -> bool:
            """Check if ACL uses the expected ACL attribute.

            Override in subclass and set ACL_ATTRIBUTE_NAME constant.

            Args:
                acl_line: ACL definition (string or model or any type)

            Returns:
                True if ACL uses the expected attribute

            """
            # Get ACL attribute name from Constants class
            constants = self._get_constants()
            if constants is None:
                return True  # No Constants class or attribute name = match all
            acl_attr_name = getattr(constants, "ACL_ATTRIBUTE_NAME", None)
            if not acl_attr_name:
                return True  # No attribute name = match all

            # String: check prefix
            if isinstance(acl_line, str):
                return acl_line.lower().startswith(acl_attr_name.lower() + ":")

            # Model with name field (AclProtocol has name attribute)
            # Type narrowed: must be AclProtocol at this point
            attr_set = frozenset([acl_attr_name])
            return self.can_handle_in_set(acl_line.name, attr_set)

    # ════════════════════════════════════════════════════════════════════════
    # Base Mixin - DRY Helper (reduces 95 lines of duplication)
    # ════════════════════════════════════════════════════════════════════════


__all__ = [
    "FlextLdifUtilitiesDetection",
]
