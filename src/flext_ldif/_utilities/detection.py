"""Detection and Identification Mixins for LDIF Server Quirks."""

from __future__ import annotations

import builtins
import re
from collections.abc import Mapping, Sequence
from typing import TypeIs

from flext_core.utilities import FlextUtilities as u_core

from flext_ldif import m, p


class FlextLdifUtilitiesDetection:
    """Detection utilities for LDIF server quirks."""

    @staticmethod
    def _is_server_constants_class(
        value: type,
        required_attr: str | None = None,
    ) -> TypeIs[type[p.Ldif.ServerConstants]]:
        if required_attr is not None:
            return getattr(value, required_attr, None) is not None
        return all(
            getattr(value, attr, None) is not None
            for attr in (
                "DETECTION_OID_PATTERN",
                "DETECTION_ATTRIBUTE_PREFIXES",
                "DETECTION_OBJECTCLASS_NAMES",
                "DETECTION_DN_MARKERS",
                "ACL_ATTRIBUTE_NAME",
            )
        )

    class BaseDetectionMixin:
        """Base mixin with shared _get_constants method."""

        def _get_constants(
            self,
            required_attr: str | None = None,
        ) -> type[p.Ldif.ServerConstants] | None:
            """Get Constants class from server class via MRO traversal."""
            for cls in type(self).__mro__:
                if (
                    cls.__name__.startswith("FlextLdifServers")
                    and getattr(cls, "Constants", None) is not None
                    and (not u_core.is_dict_like(getattr(cls, "Constants", None)))
                ):
                    constants_obj: builtins.object | None = getattr(
                        cls,
                        "Constants",
                        None,
                    )
                    if not isinstance(constants_obj, type):
                        continue
                    if FlextLdifUtilitiesDetection._is_server_constants_class(
                        constants_obj,
                        required_attr,
                    ):
                        return constants_obj
            return None

    class PatternDetectionMixin(BaseDetectionMixin):
        """Mixin for regex pattern matching across different data types."""

        @staticmethod
        def can_handle_in_set(
            data: str | m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass | None,
            items: frozenset[str],
        ) -> bool:
            """Check if data is in set (case-insensitive)."""
            if isinstance(data, str):
                items_lower = {item.lower() for item in items}
                return data.lower() in items_lower
            name = getattr(data, "name", None)
            if name:
                items_lower = {item.lower() for item in items}
                return str(name).lower() in items_lower
            try:
                if data is not None:
                    items_lower = {item.lower() for item in items}
                    return str(data).lower() in items_lower
            except (TypeError, AttributeError):
                pass
            return False

        @staticmethod
        def can_handle_pattern(
            pattern: str,
            *,
            data: str
            | m.Ldif.SchemaAttribute
            | m.Ldif.SchemaObjectClass
            | m.Ldif.Entry
            | m.Ldif.Acl
            | None,
        ) -> bool:
            """Check if data matches regex pattern."""
            try:
                if isinstance(data, str):
                    return bool(re.search(pattern, data))
                oid = getattr(data, "oid", None)
                if oid:
                    return bool(re.search(pattern, str(oid)))
                name = getattr(data, "name", None)
                if name:
                    return bool(re.search(pattern, str(name)))
                if data is not None:
                    return bool(re.search(pattern, str(data)))
                return False
            except (re.error, TypeError, AttributeError):
                return False

    class OidPatternMixin(PatternDetectionMixin):
        """Mixin for OID-based pattern detection in Schema."""

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

        def _can_handle_schema_item_by_pattern(
            self,
            schema_item: str | m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass,
        ) -> bool:
            """Generic method to check if schema item matches OID detection pattern."""
            constants = self._get_constants()
            if constants is None:
                return True
            pattern = getattr(constants, "DETECTION_OID_PATTERN", None)
            if not pattern:
                return True
            return self.can_handle_pattern(pattern, data=schema_item)

    class PrefixDetectionMixin(PatternDetectionMixin):
        """Mixin for attribute name prefix-based detection in Schema."""

        def can_handle_attribute(
            self,
            attr_definition: str | m.Ldif.SchemaAttribute,
        ) -> bool:
            """Check if attribute name matches detection prefixes."""
            constants = self._get_constants()
            if constants is None:
                return True
            prefixes = getattr(constants, "DETECTION_ATTRIBUTE_PREFIXES", None)
            if not prefixes:
                return True
            if isinstance(attr_definition, str):
                attr_name = attr_definition
            else:
                attr_name = str(attr_definition.name)
            attr_name_lower = attr_name.lower()
            return any(
                attr_name_lower.startswith(prefix.lower()) for prefix in prefixes
            )

    class ObjectClassDetectionMixin(PatternDetectionMixin):
        """Mixin for objectClass name-based detection in Entry."""

        def can_handle(
            self,
            _entry_dn: str,
            attributes: Mapping[str, Sequence[str] | str] | m.Ldif.Entry,
        ) -> bool:
            """Check if entry objectClasses match detection list."""
            if not attributes:
                return False
            constants = self._get_constants()
            if constants is None:
                return True
            detection_classes = getattr(constants, "DETECTION_OBJECTCLASS_NAMES", None)
            if not detection_classes:
                return True
            objectclasses: Sequence[str] | str | None = None
            if isinstance(attributes, m.Ldif.Entry):
                objectclasses = list(attributes.get_objectclass_names())
            else:
                obj_class = attributes.get("objectClass") or attributes.get(
                    "objectclass",
                )
                if obj_class is not None:
                    objectclasses = obj_class
            if not objectclasses:
                return False
            if isinstance(objectclasses, (list, tuple, set)):
                detection_set = {oc.lower() for oc in detection_classes}
                oc_set = {str(oc).lower() for oc in objectclasses}
                return bool(oc_set & detection_set)
            if isinstance(objectclasses, str):
                return self.can_handle_in_set(objectclasses, detection_classes)
            return False

    class DnMarkerMixin(PatternDetectionMixin):
        """Mixin for DN pattern-based detection in Entry."""

        def can_handle(
            self,
            entry_dn: str,
            _attributes: Mapping[str, Sequence[str] | str] | m.Ldif.Entry | None,
        ) -> bool:
            """Check if entry DN matches detection markers."""
            constants = self._get_constants()
            if constants is None:
                return True
            markers = getattr(constants, "DETECTION_DN_MARKERS", None)
            if not markers:
                return True
            if not entry_dn:
                return False
            dn_lower = entry_dn.lower()
            return any(marker.lower() in dn_lower for marker in markers)

    class AclDetectionMixin(PatternDetectionMixin):
        """Mixin for ACL attribute-based detection in ACL."""

        def can_handle_acl(self, acl_line: str | m.Ldif.Acl) -> bool:
            """Check if ACL uses the expected ACL attribute."""
            constants = self._get_constants()
            if constants is None:
                return True
            acl_attr_name = getattr(constants, "ACL_ATTRIBUTE_NAME", None)
            if not acl_attr_name:
                return True
            if isinstance(acl_line, str):
                return acl_line.lower().startswith(acl_attr_name.lower() + ":")
            attr_set = frozenset([acl_attr_name])
            return self.can_handle_in_set(acl_line.name, attr_set)


__all__ = ["FlextLdifUtilitiesDetection"]
