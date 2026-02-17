"""Novell eDirectory Quirks - Stub Implementation."""

from __future__ import annotations

import base64
import re
from typing import ClassVar

from flext_core import r

from flext_ldif._models.domain import FlextLdifModelsDomains
from flext_ldif.constants import c
from flext_ldif.models import m
from flext_ldif.servers.rfc import FlextLdifServersRfc
from flext_ldif.typings import t
from flext_ldif.utilities import u


class FlextLdifServersNovell(FlextLdifServersRfc):
    """Novell eDirectory quirks implementation."""

    class Constants(FlextLdifServersRfc.Constants):
        """Standardized constants for Novell eDirectory quirk."""

        SERVER_TYPE: ClassVar[str] = "novell"
        PRIORITY: ClassVar[int] = 20

        CANONICAL_NAME: ClassVar[str] = "novell_edirectory"
        ALIASES: ClassVar[frozenset[str]] = frozenset(["novell", "novell_edirectory"])
        CAN_NORMALIZE_FROM: ClassVar[frozenset[str]] = frozenset(["novell_edirectory"])
        CAN_DENORMALIZE_TO: ClassVar[frozenset[str]] = frozenset(
            [
                "novell_edirectory",
                "rfc",
            ],
        )

        ACL_FORMAT: ClassVar[str] = "aci"
        ACL_ATTRIBUTE_NAME: ClassVar[str] = "aci"

        OPERATIONAL_ATTRIBUTES: ClassVar[frozenset[str]] = frozenset(
            [
                "GUID",
                "createTimestamp",
                "modifyTimestamp",
            ],
        )

        DETECTION_OID_PATTERN: ClassVar[str] = r"2\.16\.840\.1\.113719\."
        DETECTION_PATTERN: ClassVar[str] = r"2\.16\.840\.1\.113719\."
        DETECTION_WEIGHT: ClassVar[int] = 6
        DETECTION_ATTRIBUTES: ClassVar[frozenset[str]] = frozenset(
            [
                "guid",
                "logintime",
                "logingraceremaining",
                "ndsloginproperties",
            ],
        )
        DETECTION_ATTRIBUTE_PREFIXES: ClassVar[frozenset[str]] = frozenset(
            [
                "nspm",
                "login",
                "dirxml-",
            ],
        )
        DETECTION_OBJECTCLASS_NAMES: ClassVar[frozenset[str]] = frozenset(
            [
                "ndsperson",
                "nspmpasswordpolicy",
                "ndsserver",
                "ndstree",
                "ndsloginproperties",
            ],
        )
        DETECTION_DN_MARKERS: ClassVar[frozenset[str]] = frozenset(
            [
                "ou=services",
                "ou=apps",
                "ou=system",
            ],
        )
        DETECTION_ATTRIBUTE_MARKERS: ClassVar[frozenset[str]] = frozenset(
            [
                "nspmpasswordpolicy",
                "nspmpasswordpolicydn",
                "logindisabled",
                "loginexpirationtime",
            ],
        )

        NOVELL_SEGMENT_INDEX_TRUSTEE: ClassVar[int] = 1
        NOVELL_SEGMENT_INDEX_RIGHTS: ClassVar[int] = 2

        NOVELL_SPECIFIC: ClassVar[frozenset[str]] = frozenset(
            [
                "guid",
                "nspmpasswordpolicy",
                "login",
                "nspmldapaccessgroup",
                "nspmldapuser",
                "ndsserver",
                "ndstree",
                "ndsloginproperties",
            ],
        )

        SCHEMA_ATTRIBUTE_NAME_REGEX: ClassVar[str] = r"NAME\s+\(?\s*'([^']+)'"

        ACL_DEFAULT_SUBJECT_TYPE: ClassVar[str] = "trustee"
        ACL_DEFAULT_SUBJECT_VALUE_UNKNOWN: ClassVar[str] = "unknown"

        ACL_ATTRIBUTE_NAME_WRITE: ClassVar[str] = "acl"

        ACL_ATTRIBUTE_NAMES: ClassVar[frozenset[str]] = frozenset(
            [
                "acl",
                "inheritedacl",
            ],
        )
        ACL_SEGMENT_SEPARATOR: ClassVar[str] = "#"
        ACL_DEFAULT_NAME: ClassVar[str] = "Novell eDirectory ACL"

        NOVELL_RIGHT_BROWSE: ClassVar[str] = "B"
        NOVELL_RIGHT_COMPARE: ClassVar[str] = "C"
        NOVELL_RIGHT_DELETE: ClassVar[str] = "D"
        NOVELL_RIGHT_READ: ClassVar[str] = "R"
        NOVELL_RIGHT_WRITE: ClassVar[str] = "W"
        NOVELL_RIGHT_ADD: ClassVar[str] = "A"
        NOVELL_RIGHT_SUPERVISOR: ClassVar[str] = "S"
        NOVELL_RIGHT_ENTRY: ClassVar[str] = "E"
        NOVELL_RIGHTS_BRACKET_OPEN: ClassVar[str] = "["
        NOVELL_RIGHTS_BRACKET_CLOSE: ClassVar[str] = "]"
        NOVELL_PERMISSION_SUPERVISOR: ClassVar[str] = "supervisor"
        NOVELL_PERMISSION_ENTRY: ClassVar[str] = "entry"

    class Schema(FlextLdifServersRfc.Schema):
        """Novell eDirectory schema quirk."""

        def can_handle_attribute(
            self,
            attr_definition: str | m.Ldif.SchemaAttribute,
        ) -> bool:
            """Detect eDirectory attribute definitions using Constants."""
            if not isinstance(attr_definition, str):
                if hasattr(attr_definition, "oid") and hasattr(attr_definition, "name"):
                    return u.Ldif.Server.matches_server_patterns(
                        value=attr_definition,
                        oid_pattern=FlextLdifServersNovell.Constants.DETECTION_OID_PATTERN,
                        detection_names=FlextLdifServersNovell.Constants.DETECTION_ATTRIBUTE_PREFIXES,
                        use_prefix_match=True,
                    )
                return False

            attr_lower = attr_definition.lower()
            if re.search(
                FlextLdifServersNovell.Constants.DETECTION_OID_PATTERN,
                attr_definition,
            ):
                return True
            name_matches = re.findall(
                FlextLdifServersNovell.Constants.SCHEMA_ATTRIBUTE_NAME_REGEX,
                attr_definition,
                re.IGNORECASE,
            )
            if any(
                name.lower().startswith(
                    tuple(
                        FlextLdifServersNovell.Constants.DETECTION_ATTRIBUTE_PREFIXES,
                    ),
                )
                for name in name_matches
            ):
                return True
            return any(
                prefix in attr_lower
                for prefix in FlextLdifServersNovell.Constants.DETECTION_ATTRIBUTE_PREFIXES
            )

        def can_handle_objectclass(
            self,
            oc_definition: str | m.Ldif.SchemaObjectClass,
        ) -> bool:
            """Detect eDirectory objectClass definitions using Constants."""
            if not isinstance(oc_definition, str):
                if hasattr(oc_definition, "oid") and hasattr(oc_definition, "name"):
                    return u.Ldif.Server.matches_server_patterns(
                        value=oc_definition,
                        oid_pattern=FlextLdifServersNovell.Constants.DETECTION_OID_PATTERN,
                        detection_names=FlextLdifServersNovell.Constants.DETECTION_OBJECTCLASS_NAMES,
                    )
                return False

            if re.search(
                FlextLdifServersNovell.Constants.DETECTION_OID_PATTERN,
                oc_definition,
            ):
                return True
            name_matches = re.findall(
                FlextLdifServersNovell.Constants.SCHEMA_ATTRIBUTE_NAME_REGEX,
                oc_definition,
                re.IGNORECASE,
            )
            return any(
                name.lower()
                in FlextLdifServersNovell.Constants.DETECTION_OBJECTCLASS_NAMES
                for name in name_matches
            )

        def _parse_attribute(
            self,
            attr_definition: str,
        ) -> r[m.Ldif.SchemaAttribute]:
            """Parse attribute definition and add Novell metadata."""
            result = super()._parse_attribute(attr_definition)
            if result.is_success:
                attr_data = result.value
                metadata = m.Ldif.QuirkMetadata.create_for(
                    self._get_server_type(),
                )
                return r[m.Ldif.SchemaAttribute].ok(
                    attr_data.model_copy(
                        update={"metadata": metadata},
                    ),
                )
            return result

        def _parse_objectclass(
            self,
            oc_definition: str,
        ) -> r[m.Ldif.SchemaObjectClass]:
            """Parse objectClass definition and add Novell metadata."""
            result = super()._parse_objectclass(oc_definition)
            if result.is_success:
                oc_data = result.value
                metadata = m.Ldif.QuirkMetadata.create_for(
                    self._get_server_type(),
                )
                return r[m.Ldif.SchemaObjectClass].ok(
                    oc_data.model_copy(
                        update={"metadata": metadata},
                    ),
                )
            return result

    class Acl(FlextLdifServersRfc.Acl):
        """Novell eDirectory ACL quirk."""

        def can_handle(self, acl_line: t.Ldif.AclOrString) -> bool:
            """Check if this is a Novell eDirectory ACL."""
            return self.can_handle_acl(acl_line)

        def can_handle_acl(self, acl_line: t.Ldif.AclOrString) -> bool:
            """Detect eDirectory ACL values."""
            if isinstance(acl_line, str):
                if not acl_line or not acl_line.strip():
                    return False
                normalized = acl_line.strip()
                attr_name, _, _ = normalized.partition(":")
                return (
                    attr_name.strip().lower()
                    in FlextLdifServersNovell.Constants.ACL_ATTRIBUTE_NAMES
                )

            if hasattr(acl_line, "raw_acl") and acl_line.raw_acl:
                normalized = acl_line.raw_acl.strip()
                if not normalized:
                    return False
                attr_name, _, _ = normalized.partition(":")
                return (
                    attr_name.strip().lower()
                    in FlextLdifServersNovell.Constants.ACL_ATTRIBUTE_NAMES
                )
            return False

        def _parse_acl(self, acl_line: str) -> r[m.Ldif.Acl]:
            """Parse eDirectory ACL definition."""
            try:
                attr_name, content = self.__class__.splitacl_line(acl_line)
                if not content:
                    return r[m.Ldif.Acl].fail("Empty ACL content")
                segments = [
                    segment
                    for segment in content.split(
                        FlextLdifServersNovell.Constants.ACL_SEGMENT_SEPARATOR,
                    )
                    if segment
                ]

                scope = segments[0] if segments else None

                trustee = (
                    segments[
                        FlextLdifServersNovell.Constants.NOVELL_SEGMENT_INDEX_TRUSTEE
                    ]
                    if len(segments)
                    > FlextLdifServersNovell.Constants.NOVELL_SEGMENT_INDEX_TRUSTEE
                    else None
                )

                rights_str = (
                    segments[
                        FlextLdifServersNovell.Constants.NOVELL_SEGMENT_INDEX_RIGHTS
                    ]
                    if len(segments)
                    > FlextLdifServersNovell.Constants.NOVELL_SEGMENT_INDEX_RIGHTS
                    else ""
                )

                char_mapping: dict[str, list[str]] = {
                    "B": [c.Ldif.RfcAclPermission.SEARCH],
                    "C": [c.Ldif.RfcAclPermission.COMPARE],
                    "D": [c.Ldif.RfcAclPermission.DELETE],
                    "R": [c.Ldif.RfcAclPermission.READ],
                    "W": [c.Ldif.RfcAclPermission.WRITE],
                    "A": [c.Ldif.RfcAclPermission.ADD],
                    "S": ["supervisor"],
                    "E": ["entry"],
                }

                rights: list[str] = []
                for char in rights_str:
                    char_upper = char.upper()
                    if char_upper in char_mapping:
                        rights.extend(char_mapping[char_upper])

                attributes: list[str] = []
                for right_segment in rights:
                    segment_str = str(right_segment).strip()
                    if segment_str and ":" in segment_str:
                        parts = segment_str.split(":")
                        if parts[0].strip():
                            attr_name = parts[0].strip()

                            if attr_name.lower() not in u.Enum.values(
                                c.Ldif.RfcAclPermission,
                            ):
                                attributes.append(attr_name)

                acl = m.Ldif.Acl(
                    name=FlextLdifServersNovell.Constants.ACL_DEFAULT_NAME,
                    target=m.Ldif.AclTarget(
                        target_dn=scope or "",
                        attributes=attributes,
                    ),
                    subject=m.Ldif.AclSubject(
                        subject_type="user",
                        subject_value=(
                            trustee
                            or FlextLdifServersNovell.Constants.ACL_DEFAULT_SUBJECT_VALUE_UNKNOWN
                        ),
                    ),
                    permissions=m.Ldif.AclPermissions(
                        **self._build_novell_permissions_from_rights(
                            rights,
                            {
                                "read": c.Ldif.RfcAclPermission.READ,
                                "write": c.Ldif.RfcAclPermission.WRITE,
                                "add": c.Ldif.RfcAclPermission.ADD,
                                "delete": c.Ldif.RfcAclPermission.DELETE,
                                "search": c.Ldif.RfcAclPermission.SEARCH,
                                "compare": c.Ldif.RfcAclPermission.COMPARE,
                            },
                        ),
                    ),
                    metadata=m.Ldif.QuirkMetadata.create_for(
                        self._get_server_type(),
                        extensions=m.Ldif.DynamicMetadata(
                            original_format=acl_line,
                        ),
                    ),
                    raw_acl=acl_line,
                )
                return r[m.Ldif.Acl].ok(acl)

            except (ValueError, TypeError, AttributeError) as exc:
                return r[m.Ldif.Acl].fail(
                    f"Novell eDirectory ACL parsing failed: {exc}",
                )

        def _build_novell_permissions_from_rights(
            self,
            rights: list[str],
            permission_name_map: dict[str, str],
        ) -> dict[str, bool]:
            """Build AclPermissions dict from parsed rights list."""
            reverse_map: dict[str, str] = {v: k for k, v in permission_name_map.items()}

            perms_dict: dict[str, bool] = {
                "read": False,
                "write": False,
                "add": False,
                "delete": False,
                "search": False,
                "compare": False,
            }

            for right in rights:
                if right in reverse_map:
                    canonical_name = reverse_map[right]
                    if canonical_name in perms_dict:
                        perms_dict[canonical_name] = True
            return perms_dict

        def _write_acl(self, acl_data: FlextLdifModelsDomains.Acl) -> r[str]:
            """Write ACL data to RFC-compliant string format."""
            try:
                acl_attribute = (
                    FlextLdifServersNovell.Constants.ACL_ATTRIBUTE_NAME_WRITE
                )

                if acl_data.raw_acl:
                    return r[str].ok(acl_data.raw_acl)

                parts: list[str] = []

                if acl_data.target and acl_data.target.target_dn:
                    parts.append(acl_data.target.target_dn)

                if acl_data.subject and acl_data.subject.subject_value:
                    parts.append(acl_data.subject.subject_value)

                permission_map = {
                    "read": c.Ldif.RfcAclPermission.READ,
                    "write": c.Ldif.RfcAclPermission.WRITE,
                    "add": c.Ldif.RfcAclPermission.ADD,
                    "delete": c.Ldif.RfcAclPermission.DELETE,
                    "search": c.Ldif.RfcAclPermission.SEARCH,
                    "compare": c.Ldif.RfcAclPermission.COMPARE,
                }
                active_perms: list[str] = []
                if acl_data.permissions:
                    perms_dict = acl_data.permissions.model_dump()
                    for perm_name, perm_value in perms_dict.items():
                        if perm_value is True and perm_name in permission_map:
                            active_perms.append(permission_map[perm_name])
                parts.extend(active_perms)

                acl_content = "#".join(parts) if parts else ""
                acl_str = (
                    f"{acl_attribute}: {acl_content}"
                    if acl_content
                    else f"{acl_attribute}:"
                )

                return r[str].ok(acl_str)
            except (ValueError, TypeError, AttributeError) as exc:
                return r[str].fail(
                    f"Novell eDirectory ACL write failed: {exc}",
                )

        @staticmethod
        def splitacl_line(acl_line: str) -> tuple[str, str]:
            """Split an ACL line into attribute name and payload."""
            attr_name, _, remainder = acl_line.partition(":")
            return attr_name.strip(), remainder.strip()

    class Entry(FlextLdifServersRfc.Entry):
        """Novell eDirectory entry quirk."""

        def model_post_init(self, _context: object, /) -> None:
            """Initialize eDirectory entry quirk."""

        def can_handle(
            self,
            entry_dn: str,
            attributes: dict[str, list[str]],
        ) -> bool:
            """Detect eDirectory-specific entries."""
            if not entry_dn:
                return False
            dn_lower = entry_dn.lower()
            if any(
                marker in dn_lower
                for marker in FlextLdifServersNovell.Constants.DETECTION_DN_MARKERS
            ):
                return True

            normalized_attrs = {
                name.lower(): values for name, values in attributes.items()
            }
            if any(
                marker in normalized_attrs
                for marker in FlextLdifServersNovell.Constants.DETECTION_ATTRIBUTE_MARKERS
            ):
                return True

            object_classes_raw = u.mapper().get(
                attributes,
                c.Ldif.DictKeys.OBJECTCLASS,
                default=[],
            )

            if isinstance(object_classes_raw, (list, tuple)):
                object_classes: list[str] = [str(item) for item in object_classes_raw]
            else:
                object_classes = []
            return bool(
                any(
                    str(oc).lower()
                    in FlextLdifServersNovell.Constants.DETECTION_OBJECTCLASS_NAMES
                    for oc in object_classes
                ),
            )

        def process_entry(
            self,
            entry: m.Ldif.Entry,
        ) -> r[m.Ldif.Entry]:
            """Normalise eDirectory entries and expose metadata."""
            if not entry.attributes:
                return r[m.Ldif.Entry].ok(entry)

            attributes = entry.attributes.attributes.copy()
            try:
                object_classes_raw = u.mapper().get(
                    attributes,
                    c.Ldif.DictKeys.OBJECTCLASS,
                    default=[],
                )

                if isinstance(object_classes_raw, list):
                    object_classes: list[str] = [str(oc) for oc in object_classes_raw]
                else:
                    object_classes = []

                processed_attributes: dict[str, list[str]] = {}
                for attr_name, attr_values in attributes.items():
                    processed_values: list[str] = []

                    value: bytes | str
                    for value in attr_values:
                        str_value: str
                        if isinstance(value, bytes):
                            str_value = base64.b64encode(value).decode("ascii")
                        else:
                            str_value = str(value)
                        processed_values.append(str_value)
                    processed_attributes[attr_name] = processed_values

                processed_attributes[c.Ldif.Domain.QuirkMetadataKeys.SERVER_TYPE] = [
                    self._get_server_type(),
                ]
                processed_attributes[c.Ldif.DictKeys.OBJECTCLASS] = object_classes

                new_attrs = m.Ldif.Attributes(
                    attributes=processed_attributes,
                )
                new_entry = entry.model_copy(
                    update={"attributes": new_attrs},
                )
                return r[m.Ldif.Entry].ok(new_entry)

            except (ValueError, TypeError, AttributeError) as exc:
                return r[m.Ldif.Entry].fail(
                    f"Novell eDirectory entry processing failed: {exc}",
                )
