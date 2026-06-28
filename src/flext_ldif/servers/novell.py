"""Novell eDirectory Servers — eDirectory flavor detection and schema handling."""

from __future__ import annotations

from typing import ClassVar, override

from flext_ldif import FlextLdifServersRfc, c, m, p, r, t, u


class FlextLdifServersNovell(FlextLdifServersRfc):
    """Novell eDirectory servers implementation."""

    class Constants(FlextLdifServersRfc.Constants):
        """Standardized constants for Novell eDirectory server."""

        SERVER_TYPE: ClassVar[str] = "novell"
        PRIORITY: ClassVar[int] = 20
        CANONICAL_NAME: ClassVar[str] = "novell_edirectory"
        ALIASES: ClassVar[frozenset[str]] = frozenset(["novell", "novell_edirectory"])
        CAN_NORMALIZE_FROM: ClassVar[frozenset[str]] = frozenset(["novell_edirectory"])
        CAN_DENORMALIZE_TO: ClassVar[frozenset[str]] = frozenset([
            "novell_edirectory",
            "rfc",
        ])
        ACL_FORMAT: ClassVar[str] = "aci"
        ACL_ATTRIBUTE_NAME: ClassVar[str] = "aci"
        OPERATIONAL_ATTRIBUTES: ClassVar[frozenset[str]] = frozenset([
            "GUID",
            "createTimestamp",
            "modifyTimestamp",
        ])
        DETECTION_OID_PATTERN: ClassVar[str] = "2\\.16\\.840\\.1\\.113719\\."
        DETECTION_PATTERN: ClassVar[str] = "2\\.16\\.840\\.1\\.113719\\."
        DETECTION_WEIGHT: ClassVar[int] = 6
        DETECTION_ATTRIBUTES: ClassVar[frozenset[str]] = frozenset([
            "guid",
            "logintime",
            "logingraceremaining",
            "ndsloginproperties",
        ])
        DETECTION_ATTRIBUTE_PREFIXES: ClassVar[frozenset[str]] = frozenset([
            "nspm",
            "login",
            "dirxml-",
        ])
        DETECTION_OBJECTCLASS_NAMES: ClassVar[frozenset[str]] = frozenset([
            "ndsperson",
            "nspmpasswordpolicy",
            "ndsserver",
            "ndstree",
            "ndsloginproperties",
        ])
        SCHEMA_ATTRIBUTE_NAME_REGEX: ClassVar[str] = "NAME\\s+\\(?\\s*'([^']+)'"
        ATTRIBUTE_PATTERN_SETTINGS: ClassVar[m.Ldif.ServerPatternsConfig] = (
            m.Ldif.ServerPatternsConfig(
                oid_pattern=DETECTION_OID_PATTERN,
                attr_prefixes=DETECTION_ATTRIBUTE_PREFIXES,
                name_regex=SCHEMA_ATTRIBUTE_NAME_REGEX,
                use_prefix_match=True,
                match_definition_text=True,
            )
        )
        OBJECTCLASS_PATTERN_SETTINGS: ClassVar[m.Ldif.ServerPatternsConfig] = (
            m.Ldif.ServerPatternsConfig(
                oid_pattern=DETECTION_OID_PATTERN,
                attr_names=DETECTION_OBJECTCLASS_NAMES,
                name_regex=SCHEMA_ATTRIBUTE_NAME_REGEX,
            )
        )
        DETECTION_DN_MARKERS: ClassVar[frozenset[str]] = frozenset([
            "ou=services",
            "ou=apps",
            "ou=system",
        ])
        DETECTION_ATTRIBUTE_MARKERS: ClassVar[frozenset[str]] = frozenset([
            "nspmpasswordpolicy",
            "nspmpasswordpolicydn",
            "logindisabled",
            "loginexpirationtime",
        ])
        NOVELL_SEGMENT_INDEX_TRUSTEE: ClassVar[int] = 1
        NOVELL_SEGMENT_INDEX_RIGHTS: ClassVar[int] = 2
        NOVELL_SPECIFIC: ClassVar[frozenset[str]] = frozenset([
            "guid",
            "nspmpasswordpolicy",
            "login",
            "nspmldapaccessgroup",
            "nspmldapuser",
            "ndsserver",
            "ndstree",
            "ndsloginproperties",
        ])
        ACL_DEFAULT_SUBJECT_TYPE: ClassVar[str] = "trustee"
        ACL_DEFAULT_SUBJECT_VALUE_UNKNOWN: ClassVar[str] = c.Ldif.UNKNOWN_VALUE
        ACL_ATTRIBUTE_NAME_WRITE: ClassVar[str] = "acl"
        ACL_ATTRIBUTE_NAMES: ClassVar[frozenset[str]] = frozenset([
            "acl",
            "inheritedacl",
        ])
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
        """Novell eDirectory schema server."""

        @override
        def can_handle_attribute(
            self,
            attr_definition: str | m.Ldif.SchemaAttribute,
        ) -> bool:
            """Detect eDirectory attribute definitions using Constants."""
            matches: bool = u.Ldif.matches_server_patterns(
                value=attr_definition,
                settings=FlextLdifServersNovell.Constants.ATTRIBUTE_PATTERN_SETTINGS,
            )
            return matches

        @override
        def can_handle_objectclass(
            self,
            oc_definition: str | m.Ldif.SchemaObjectClass,
        ) -> bool:
            """Detect eDirectory objectClass definitions using Constants."""
            matches: bool = u.Ldif.matches_server_patterns(
                value=oc_definition,
                settings=FlextLdifServersNovell.Constants.OBJECTCLASS_PATTERN_SETTINGS,
            )
            return matches

    class Acl(FlextLdifServersRfc.Acl):
        """Novell eDirectory ACL server."""

        @staticmethod
        def splitacl_line(acl_line: str) -> t.StrPair:
            """Split an ACL line into attribute name and payload."""
            attr_name, _, remainder = acl_line.partition(":")
            return (attr_name.strip(), remainder.strip())

        @override
        def can_handle(self, acl_line: str | m.Ldif.Acl) -> bool:
            """Check if this is a Novell eDirectory ACL."""
            return self.can_handle_acl(acl_line)

        @override
        def can_handle_acl(self, acl_line: str | m.Ldif.Acl) -> bool:
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
            raw_acl = getattr(acl_line, "raw_acl", None)
            if not isinstance(raw_acl, str) or not raw_acl:
                return False
            normalized = raw_acl.strip()
            if not normalized:
                return False
            attr_name, _, _ = normalized.partition(":")
            return (
                attr_name.strip().lower()
                in FlextLdifServersNovell.Constants.ACL_ATTRIBUTE_NAMES
            )

        def _build_novell_permissions_from_rights(
            self,
            rights: t.MutableSequenceOf[str],
            permission_name_map: t.MutableStrMapping,
        ) -> t.MutableBoolMapping:
            """Build AclPermissions dict from parsed rights list."""
            reverse_map: t.MutableStrMapping = {
                v: k for k, v in permission_name_map.items()
            }
            perms_dict: t.MutableBoolMapping = {
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

        @override
        def _parse_acl(self, acl_line: str) -> p.Result[m.Ldif.Acl]:
            """Parse eDirectory ACL definition."""
            try:
                return self._parse_novell_acl(acl_line)
            except c.EXC_BASIC_TYPE as exc:
                return r[m.Ldif.Acl].fail_op("Novell eDirectory ACL parsing", exc)

        @override
        def _write_acl(self, acl_data: m.Ldif.Acl) -> p.Result[str]:
            """Write ACL data to RFC-compliant string format."""
            try:
                return self._write_novell_acl(acl_data)
            except c.EXC_BASIC_TYPE as exc:
                return r[str].fail_op("Novell eDirectory ACL write", exc)

        def _parse_novell_acl(self, acl_line: str) -> p.Result[m.Ldif.Acl]:
            """Parse Novell eDirectory ACL content."""
            attr_name, content = self.__class__.splitacl_line(acl_line)
            _ = attr_name
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
            trustee = self._segment_at(
                segments,
                FlextLdifServersNovell.Constants.NOVELL_SEGMENT_INDEX_TRUSTEE,
            )
            rights_str = (
                self._segment_at(
                    segments,
                    FlextLdifServersNovell.Constants.NOVELL_SEGMENT_INDEX_RIGHTS,
                )
                or ""
            )
            rights = self._parse_novell_rights(rights_str)
            attributes = self._parse_novell_acl_attributes(rights)
            acl = m.Ldif.Acl(
                name=FlextLdifServersNovell.Constants.ACL_DEFAULT_NAME,
                target=m.Ldif.AclTarget.model_validate({
                    "target_dn": scope or "",
                    "attributes": attributes,
                }),
                subject=m.Ldif.AclSubject(
                    subject_type=c.Ldif.AclSubjectType.USER,
                    subject_value=trustee
                    or FlextLdifServersNovell.Constants.ACL_DEFAULT_SUBJECT_VALUE_UNKNOWN,
                ),
                permissions=m.Ldif.AclPermissions(
                    **self._build_novell_permissions_from_rights(
                        rights,
                        self._NOVELL_PERMISSION_MAP,
                    ),
                ),
                metadata=m.Ldif.ServerMetadata.create_for(
                    self._get_server_type(),
                    extensions=m.Ldif.DynamicMetadata(original_format=acl_line),
                ),
                raw_acl=acl_line,
            )
            return r[m.Ldif.Acl].ok(acl)

        _NOVELL_RIGHT_CHAR_MAP: ClassVar[t.StrSequenceMapping] = {
            "B": (c.Ldif.RfcAclPermission.SEARCH,),
            "C": (c.Ldif.RfcAclPermission.COMPARE,),
            "D": (c.Ldif.RfcAclPermission.DELETE,),
            "R": (c.Ldif.RfcAclPermission.READ,),
            "W": (c.Ldif.RfcAclPermission.WRITE,),
            "A": (c.Ldif.RfcAclPermission.ADD,),
            "S": ("supervisor",),
            "E": ("entry",),
        }
        _NOVELL_PERMISSION_MAP: ClassVar[t.StrMapping] = {
            "read": c.Ldif.RfcAclPermission.READ,
            "write": c.Ldif.RfcAclPermission.WRITE,
            "add": c.Ldif.RfcAclPermission.ADD,
            "delete": c.Ldif.RfcAclPermission.DELETE,
            "search": c.Ldif.RfcAclPermission.SEARCH,
            "compare": c.Ldif.RfcAclPermission.COMPARE,
        }

        @staticmethod
        def _segment_at(
            segments: t.MutableSequenceOf[str],
            index: int,
        ) -> str | None:
            """Return segment at index when present."""
            if len(segments) > index:
                return segments[index]
            return None

        @classmethod
        def _parse_novell_rights(cls, rights_str: str) -> t.MutableSequenceOf[str]:
            """Parse Novell rights characters into canonical rights."""
            rights: t.MutableSequenceOf[str] = []
            for char in rights_str:
                char_upper = char.upper()
                if char_upper in cls._NOVELL_RIGHT_CHAR_MAP:
                    rights.extend(cls._NOVELL_RIGHT_CHAR_MAP[char_upper])
            return rights

        @staticmethod
        def _parse_novell_acl_attributes(
            rights: t.MutableSequenceOf[str],
        ) -> t.MutableSequenceOf[str]:
            """Extract attribute names encoded in rights segments."""
            attributes: t.MutableSequenceOf[str] = []
            for right_segment in rights:
                segment_str = right_segment.strip()
                if segment_str and ":" in segment_str:
                    parts = segment_str.split(":")
                    if parts[0].strip():
                        attr_name = parts[0].strip()
                        if attr_name.lower() not in u.enum_values(
                            c.Ldif.RfcAclPermission,
                        ):
                            attributes.append(attr_name)
            return attributes

        def _write_novell_acl(self, acl_data: m.Ldif.Acl) -> p.Result[str]:
            """Write Novell eDirectory ACL content."""
            acl_attribute = FlextLdifServersNovell.Constants.ACL_ATTRIBUTE_NAME_WRITE
            if acl_data.raw_acl:
                return r[str].ok(acl_data.raw_acl)
            parts: t.MutableSequenceOf[str] = []
            if acl_data.target and acl_data.target.target_dn:
                parts.append(acl_data.target.target_dn)
            if acl_data.subject and acl_data.subject.subject_value:
                parts.append(acl_data.subject.subject_value)
            parts.extend(self._active_novell_permissions(acl_data.permissions))
            acl_content = "#".join(parts) if parts else ""
            acl_str = (
                f"{acl_attribute}: {acl_content}"
                if acl_content
                else f"{acl_attribute}:"
            )
            return r[str].ok(acl_str)

        @classmethod
        def _active_novell_permissions(
            cls,
            permissions: m.Ldif.AclPermissions | None,
        ) -> t.MutableSequenceOf[str]:
            """Return active Novell permission tokens."""
            active_perms: t.MutableSequenceOf[str] = []
            if not permissions:
                return active_perms
            perms_dict = {
                key: getattr(permissions, key) for key in type(permissions).model_fields
            }
            for perm_name, perm_value in perms_dict.items():
                if perm_value is True and perm_name in cls._NOVELL_PERMISSION_MAP:
                    active_perms.append(cls._NOVELL_PERMISSION_MAP[perm_name])
            return active_perms

    class Entry(FlextLdifServersRfc.Entry):
        """Novell eDirectory entry server."""

        @override
        def can_handle(
            self,
            entry_dn: str,
            attributes: t.MutableStrSequenceMapping,
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
            object_classes = attributes.get(c.Ldif.DictKeys.OBJECTCLASS, [])
            return any(
                oc.lower()
                in FlextLdifServersNovell.Constants.DETECTION_OBJECTCLASS_NAMES
                for oc in object_classes
            )

        @override
        def model_post_init(
            self,
            __context: t.JsonMapping | None,
            /,
        ) -> None:
            """Initialize eDirectory entry server."""

        def process_entry(self, entry: m.Ldif.Entry) -> p.Result[m.Ldif.Entry]:
            """Normalise eDirectory entries and expose metadata."""
            if not entry.attributes:
                return r[m.Ldif.Entry].ok(entry)
            attributes: t.MutableStrSequenceMapping = {
                **entry.attributes.attributes,
            }
            try:
                return self._process_novell_entry(entry, attributes)
            except c.EXC_BASIC_TYPE as exc:
                return r[m.Ldif.Entry].fail_op(
                    "Novell eDirectory entry processing", exc
                )

        def _process_novell_entry(
            self,
            entry: m.Ldif.Entry,
            attributes: t.MutableStrSequenceMapping,
        ) -> p.Result[m.Ldif.Entry]:
            """Normalize eDirectory entry attributes."""
            object_classes = attributes.get(c.Ldif.DictKeys.OBJECTCLASS, [])
            processed_attributes: t.MutableStrSequenceMapping = {}
            for attr_name, attr_values in attributes.items():
                processed_values: t.MutableSequenceOf[str] = list(attr_values)
                processed_attributes[attr_name] = processed_values
            processed_attributes[c.Ldif.ServerMetadataKeys.SERVER_TYPE] = [
                self._get_server_type(),
            ]
            processed_attributes[c.Ldif.DictKeys.OBJECTCLASS] = object_classes
            new_attrs = m.Ldif.Attributes.model_validate({
                "attributes": processed_attributes,
            })
            new_entry = entry.model_copy(update={"attributes": new_attrs})
            return r[m.Ldif.Entry].ok(new_entry)
