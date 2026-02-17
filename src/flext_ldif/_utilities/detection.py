"""Detection and Identification Mixins for LDIF Server Quirks."""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence

from flext_core import FlextRuntime

from flext_ldif.models import m
from flext_ldif.protocols import p


class FlextLdifUtilitiesDetection:
    """Detection utilities for LDIF server quirks."""

    class BaseDetectionMixin:
        """Base mixin with shared _get_constants method."""

        def _get_constants(
            self,
            required_attr: str | None = None,
        ) -> type[p.Ldif.ServerConstantsProtocol] | None:
            """Get Constants class from server class via MRO traversal."""
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
        """Mixin for regex pattern matching across different data types."""

        @staticmethod
        def can_handle_pattern(
            pattern: str,
            *,
            data: (
                str
                | m.Ldif.SchemaAttribute
                | m.Ldif.SchemaObjectClass
                | m.Ldif.Entry
                | m.Ldif.Acl
                | None
            ),
        ) -> bool:
            """Check if data matches regex pattern."""
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
        def can_handle_in_set(
            data: (str | m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass | None),
            items: frozenset[str],
        ) -> bool:
            """Check if data is in set (case-insensitive)."""
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
        """Mixin for OID-based pattern detection in Schema."""

        def _can_handle_schema_item_by_pattern(
            self,
            schema_item: (str | m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass),
        ) -> bool:
            """Generic method to check if schema item matches OID detection pattern."""
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
            attr_definition: str | m.Ldif.SchemaAttribute,
        ) -> bool:
            """Check if attribute matches OID detection pattern."""
            return self._can_handle_schema_item_by_pattern(attr_definition)

        def can_handle_objectclass(
            self,
            oc_definition: str | m.Ldif.SchemaObjectClass,
        ) -> bool:
            """Check if objectClass matches OID detection pattern."""
            return self._can_handle_schema_item_by_pattern(oc_definition)

    class PrefixDetectionMixin(PatternDetectionMixin):
        """Mixin for attribute name prefix-based detection in Schema."""

        def can_handle_attribute(
            self,
            attr_definition: str | m.Ldif.SchemaAttribute,
        ) -> bool:
            """Check if attribute name matches detection prefixes."""
            # Get prefixes from Constants class
            constants = self._get_constants()
            if constants is None:
                return True  # No Constants class or prefixes = match all
            prefixes = getattr(constants, "DETECTION_ATTRIBUTE_PREFIXES", None)
            if not prefixes:
                return True  # No prefixes = match all
            # Type narrowing: SchemaAttribute structurally implements SchemaAttributeProtocol
            # Extract name for prefix matching
            if isinstance(attr_definition, str):
                attr_name = attr_definition
            else:
                # SchemaAttribute has .name attribute matching protocol
                attr_name = attr_definition.name
            # Check prefix match directly
            attr_name_lower = attr_name.lower()
            return any(
                attr_name_lower.startswith(prefix.lower()) for prefix in prefixes
            )

    class ObjectClassDetectionMixin(PatternDetectionMixin):
        """Mixin for objectClass name-based detection in Entry."""

        def can_handle(
            self,
            _entry_dn: str,
            attributes: (
                Mapping[str, Sequence[str] | str]
                | dict[str, Sequence[str] | str]
                | m.Ldif.Entry
            ),
        ) -> bool:
            """Check if entry objectClasses match detection list."""
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
            if isinstance(attributes, m.Ldif.Entry):
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
        """Mixin for DN pattern-based detection in Entry."""

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
            """Check if entry DN matches detection markers."""
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
        """Mixin for ACL attribute-based detection in ACL."""

        def can_handle_acl(
            self,
            acl_line: str | m.Ldif.Acl,
        ) -> bool:
            """Check if ACL uses the expected ACL attribute."""
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
