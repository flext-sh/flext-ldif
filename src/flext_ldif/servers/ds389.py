"""389 Directory Server Servers — DS389 flavor detection and schema handling."""

from __future__ import annotations

import re
from typing import ClassVar, override

from flext_ldif import c, m, p, r, t, u
from flext_ldif.servers.rfc import FlextLdifServersRfc


class FlextLdifServersDs389(FlextLdifServersRfc):
    """389 Directory Server servers implementation."""

    class Constants(FlextLdifServersRfc.Constants):
        """Standardized constants for 389 Directory Server server."""

        SERVER_TYPE: ClassVar[str] = "ds389"
        PRIORITY: ClassVar[int] = 30
        CANONICAL_NAME: ClassVar[str] = "389ds"
        ALIASES: ClassVar[frozenset[str]] = frozenset(["389ds"])
        CAN_NORMALIZE_FROM: ClassVar[frozenset[str]] = frozenset(["389ds"])
        CAN_DENORMALIZE_TO: ClassVar[frozenset[str]] = frozenset(["389ds", "rfc"])
        ACL_FORMAT: ClassVar[str] = "aci"
        ACL_ATTRIBUTE_NAME: ClassVar[str] = "aci"
        OPERATIONAL_ATTRIBUTES: ClassVar[frozenset[str]] = frozenset([
            "createTimestamp",
            "modifyTimestamp",
            "creatorsName",
            "modifiersName",
            "nsUniqueId",
            "entryid",
            "dncomp",
            "parentid",
            "passwordExpirationTime",
            "passwordHistory",
            "nscpEntryDN",
            "nsds5ReplConflict",
        ])
        SUPPORTED_PERMISSIONS: ClassVar[frozenset[str]] = (
            FlextLdifServersRfc.Constants.SUPPORTED_PERMISSIONS
            | frozenset(["proxy", "all"])
        )
        DETECTION_OID_PATTERN: ClassVar[str] = "2\\.16\\.840\\.1\\.113730\\."
        DETECTION_ATTRIBUTE_PREFIXES: ClassVar[frozenset[str]] = frozenset([
            "nsslapd-",
            "nsds",
            "nsuniqueid",
        ])
        DETECTION_PATTERN: ClassVar[str] = "\\b(389ds|redhat-ds|dirsrv)\\b"
        DETECTION_ATTRIBUTES: ClassVar[frozenset[str]] = frozenset([
            "nsuniqueId",
            "nsslapd-",
            "nsds5replica",
            "nsds5replicationagreement",
        ])
        DETECTION_WEIGHT: ClassVar[int] = 6
        DETECTION_OBJECTCLASS_NAMES: ClassVar[frozenset[str]] = frozenset([
            "nscontainer",
            "nsperson",
            "nsds5replica",
            "nsds5replicationagreement",
            "nsorganizationalunit",
            "nsorganizationalperson",
        ])
        SCHEMA_ATTRIBUTE_NAME_REGEX: ClassVar[str] = "NAME\\s+['\\\"]([\\w-]+)['\\\"]"
        SCHEMA_OBJECTCLASS_NAME_REGEX: ClassVar[str] = "NAME\\s+['\\\"](\\w+)['\\\"]"
        ATTRIBUTE_PATTERN_SETTINGS: ClassVar[p.Ldif.ServerPatternsConfig] = (
            m.Ldif.ServerPatternsConfig(
                oid_pattern=DETECTION_OID_PATTERN,
                attr_prefixes=DETECTION_ATTRIBUTE_PREFIXES,
                name_regex=SCHEMA_ATTRIBUTE_NAME_REGEX,
                use_prefix_match=True,
            )
        )
        OBJECTCLASS_PATTERN_SETTINGS: ClassVar[p.Ldif.ServerPatternsConfig] = (
            m.Ldif.ServerPatternsConfig(
                oid_pattern=DETECTION_OID_PATTERN,
                attr_names=DETECTION_OBJECTCLASS_NAMES,
                name_regex=SCHEMA_OBJECTCLASS_NAME_REGEX,
            )
        )
        DETECTION_DN_MARKERS: ClassVar[frozenset[str]] = frozenset([
            "cn=settings",
            "cn=monitor",
            "cn=changelog",
        ])
        SCHEMA_DN: ClassVar[str] = "cn=subschemasubentry"
        ATTRIBUTE_FIELDS: ClassVar[frozenset[str]] = frozenset(["x_origin", "x_ds_use"])
        ACL_SUBJECT_TYPE_USER: ClassVar[str] = "user"
        ACL_SUBJECT_TYPE_GROUP: ClassVar[str] = "group"
        ACL_SUBJECT_TYPE_SELF: ClassVar[str] = "self"
        ACL_SUBJECT_TYPE_ANONYMOUS: ClassVar[str] = "anyone"
        DS_389_SPECIFIC: ClassVar[frozenset[str]] = frozenset([
            "nsuniqueId",
            "nscpentrydn",
            "nsds5replconflict",
            "nsds5replicareferencen",
            "nsds5beginreplicarefresh",
            "nsds7windowsreplicasubentry",
            "nsds7DirectoryReplicaSubentry",
        ])
        ACL_CLAUSE_PATTERN: ClassVar[str] = "\\([^()]+\\)"
        ACL_NAME_PATTERN: ClassVar[str] = 'acl\\s+\\"([^\\"]+)\\"'
        ACL_NAME_RE: ClassVar[t.Ldif.RegexPattern] = re.compile(
            ACL_NAME_PATTERN, re.IGNORECASE
        )
        ACL_ALLOW_PATTERN: ClassVar[str] = "allow\\s*\\(([^)]+)\\)"
        ACL_ALLOW_RE: ClassVar[t.Ldif.RegexPattern] = re.compile(
            ACL_ALLOW_PATTERN, re.IGNORECASE
        )
        ACL_TARGETATTR_PATTERN: ClassVar[str] = 'targetattr\\s*=\\s*\\"([^\\"]+)\\"'
        ACL_TARGETATTR_RE: ClassVar[t.Ldif.RegexPattern] = re.compile(
            ACL_TARGETATTR_PATTERN, re.IGNORECASE
        )
        ACL_USERDN_PATTERN: ClassVar[str] = 'userdn\\s*=\\s*\\"([^\\"]+)\\"'
        ACL_USERDN_RE: ClassVar[t.Ldif.RegexPattern] = re.compile(
            ACL_USERDN_PATTERN, re.IGNORECASE
        )
        ACL_TARGET_PATTERN: ClassVar[str] = 'target\\s*=\\s*\\"([^\\"]+)\\"'
        ACL_TARGET_RE: ClassVar[t.Ldif.RegexPattern] = re.compile(
            ACL_TARGET_PATTERN, re.IGNORECASE
        )
        ACL_DEFAULT_NAME: ClassVar[str] = "389 DS ACL"
        ACL_TARGET_DN_PREFIX: ClassVar[str] = "dn:"
        ACL_ANONYMOUS_SUBJECT: ClassVar[str] = "ldap:///anyone"
        ACL_VERSION_PREFIX: ClassVar[str] = "(version 3.0)"
        ACL_TARGETATTR_SEPARATOR: ClassVar[str] = ","
        ACL_TARGETATTR_SPACE_REPLACEMENT: ClassVar[str] = " "
        ACL_ACI_PREFIX: ClassVar[str] = "aci:"
        ACL_ALLOW_PREFIX: ClassVar[str] = "allow"
        ACL_TARGETATTR_PREFIX: ClassVar[str] = "targetattr"
        ACL_USERDN_PREFIX: ClassVar[str] = "userdn"
        ACL_TARGET_PREFIX: ClassVar[str] = 'target = "'
        ACL_WILDCARD_ATTRIBUTE: ClassVar[str] = "*"
        ERROR_ACL_PARSING_FAILED: ClassVar[str] = (
            "389 Directory Server ACL parsing failed: {exc}"
        )
        ERROR_ACL_WRITE_FAILED: ClassVar[str] = (
            "389 Directory Server ACL write failed: {exc}"
        )
        ERROR_ENTRY_PROCESSING_FAILED: ClassVar[str] = (
            "389 Directory Server entry processing failed: {exc}"
        )

    class Schema(FlextLdifServersRfc.Schema):
        """Schema servers for Red Hat / 389 Directory Server."""

        @override
        def can_handle_attribute(
            self, attr_definition: str | p.Ldif.SchemaAttribute
        ) -> bool:
            """Detect 389 DS attribute definitions using centralized constants."""
            matches: bool = u.Ldif.matches_server_patterns(
                value=attr_definition,
                settings=FlextLdifServersDs389.Constants.ATTRIBUTE_PATTERN_SETTINGS,
            )
            return matches

        @override
        def can_handle_objectclass(
            self, oc_definition: str | p.Ldif.SchemaObjectClass
        ) -> bool:
            """Detect 389 DS objectClass definitions using centralized constants."""
            matches: bool = u.Ldif.matches_server_patterns(
                value=oc_definition,
                settings=FlextLdifServersDs389.Constants.OBJECTCLASS_PATTERN_SETTINGS,
            )
            return matches

        @override
        def _hook_post_parse_objectclass(
            self,
            # NOTE (multi-agent, mro-0ftd.3.7.2): protocol payload (§3.2).
            oc: p.Ldif.SchemaObjectClass,
        ) -> p.Result[p.Ldif.SchemaObjectClass]:
            """Normalize 389 DS objectClass data after RFC parsing."""
            # NOTE (multi-agent, mro-0ftd.3.7.2): helpers return the immutable
            # model_copy transition (no in-place mutation) — assign it.
            oc = u.Ldif.fix_missing_sup(oc)
            oc = u.Ldif.fix_kind_mismatch(oc)
            return super()._hook_post_parse_objectclass(oc)

    class Acl(FlextLdifServersRfc.Acl):
        """389 Directory Server ACI server."""

        @staticmethod
        def _resolve_acl_targetattr(target: p.Ldif.AclTarget | None) -> str:
            """Resolve target attributes to formatted string."""
            if target and target.attributes:
                separator = (
                    FlextLdifServersDs389.Constants.ACL_TARGETATTR_SPACE_REPLACEMENT
                )
                return separator.join(target.attributes)
            return FlextLdifServersDs389.Constants.ACL_WILDCARD_ATTRIBUTE

        @staticmethod
        def _resolve_acl_userdn(subject: p.Ldif.AclSubject | None) -> str:
            """Resolve subject to userdn string."""
            if subject and subject.subject_value:
                subject_value: str = subject.subject_value
                return subject_value
            anonymous_subject: str = (
                FlextLdifServersDs389.Constants.ACL_ANONYMOUS_SUBJECT
            )
            return anonymous_subject

        @override
        # NOTE (multi-agent, mro-0ftd.3.7.2): protocol payload to match base SSOT.
        def can_handle(self, acl_line: str | p.Ldif.Acl) -> bool:
            """Check if this is a 389 Directory Server ACL (public method)."""
            return self.can_handle_acl(acl_line)

        @override
        def can_handle_acl(self, acl_line: str | p.Ldif.Acl) -> bool:
            """Detect 389 DS ACI lines."""
            if isinstance(acl_line, str):
                normalized = acl_line.strip()
            else:
                raw_acl = getattr(acl_line, "raw_acl", None)
                if not isinstance(raw_acl, str):
                    return False
                normalized = raw_acl.strip()
            if not normalized:
                return False
            attr_name, _, _ = normalized.partition(":")
            if (
                attr_name.strip().lower()
                == FlextLdifServersDs389.Constants.ACL_ATTRIBUTE_NAME
            ):
                return True
            return normalized.lower().startswith("(version")

        def _build_acl_string(
            self,
            acl_name: str,
            permissions: t.MutableSequenceOf[str],
            targetattr: str,
            userdn: str,
        ) -> p.Result[str]:
            """Build ACI string from components."""
            version_prefix = FlextLdifServersDs389.Constants.ACL_VERSION_PREFIX
            parts = [version_prefix, f'acl "{acl_name}"']
            if permissions:
                perms = FlextLdifServersDs389.Constants.ACL_TARGETATTR_SEPARATOR.join(
                    permissions
                )
                parts.append(
                    f"{FlextLdifServersDs389.Constants.ACL_ALLOW_PREFIX} ({perms})"
                )
            if targetattr:
                prefix = FlextLdifServersDs389.Constants.ACL_TARGETATTR_PREFIX
                parts.append(f'{prefix} = "{targetattr}"')
            if userdn:
                parts.append(
                    f'{FlextLdifServersDs389.Constants.ACL_USERDN_PREFIX} = "{userdn}"'
                )
            acl_separator = FlextLdifServersDs389.Constants.ACL_TARGETATTR_SEPARATOR
            acl_content = f"{acl_separator} ".join(parts) if parts else ""
            acl_str = (
                f"{FlextLdifServersDs389.Constants.ACL_ACI_PREFIX} {acl_content}"
                if acl_content
                else FlextLdifServersDs389.Constants.ACL_ACI_PREFIX
            )
            return r[str].ok(acl_str)

        def _extract_acl_permissions(
            self, permissions_data: p.Ldif.AclPermissions | None
        ) -> t.MutableSequenceOf[str]:
            """Extract permission names from Permissions model flags."""
            permissions: t.MutableSequenceOf[str] = []
            if not permissions_data:
                return permissions
            if permissions_data.read:
                permissions.append("read")
            if permissions_data.write:
                permissions.append("write")
            if permissions_data.add:
                permissions.append("add")
            if permissions_data.delete:
                permissions.append("delete")
            if permissions_data.search:
                permissions.append("search")
            if permissions_data.compare:
                permissions.append("compare")
            return permissions

        @override
        def _parse_acl(self, acl_line: str) -> p.Result[p.Ldif.Acl]:
            """Parse 389 DS ACI definition."""
            try:
                return self._parse_ds389_acl(acl_line)
            except c.EXC_BASIC_TYPE as exc:
                return r[p.Ldif.Acl].fail(
                    FlextLdifServersDs389.Constants.ERROR_ACL_PARSING_FAILED.format(
                        exc=exc
                    )
                )

        @override
        def _write_acl(self, acl_data: p.Ldif.Acl) -> p.Result[str]:
            """Write ACL data to RFC-compliant string format."""
            try:
                return self._write_ds389_acl(acl_data)
            except c.EXC_BASIC_TYPE as exc:
                return r[str].fail(
                    FlextLdifServersDs389.Constants.ERROR_ACL_WRITE_FAILED.format(
                        exc=exc
                    )
                )

        def _parse_ds389_acl(self, acl_line: str) -> p.Result[p.Ldif.Acl]:
            """Parse 389 DS ACI content into a canonical ACL."""
            attr_name, content = u.Ldif.split_acl_line(acl_line)
            _ = attr_name
            acl_name_match = FlextLdifServersDs389.Constants.ACL_NAME_RE.search(content)
            permissions_match = FlextLdifServersDs389.Constants.ACL_ALLOW_RE.search(
                content
            )
            permissions: t.MutableSequenceOf[str] = (
                [
                    perm.strip()
                    for perm in permissions_match.group(1).split(
                        FlextLdifServersDs389.Constants.ACL_TARGETATTR_SEPARATOR
                    )
                ]
                if permissions_match
                else []
            )
            target_attributes = self._parse_target_attributes(content)
            target_dn = self._parse_target_dn(content)
            metadata = u.Ldif.server_metadata_for(self._get_server_type())
            metadata.extensions["original_format"] = acl_line.strip()
            acl_name = (
                acl_name_match.group(1)
                if acl_name_match
                else FlextLdifServersDs389.Constants.ACL_DEFAULT_NAME
            )
            permissions_data = m.Ldif.AclPermissions(
                read="read" in permissions,
                write="write" in permissions,
                add="add" in permissions,
                delete="delete" in permissions,
                search="search" in permissions,
                compare="compare" in permissions,
            )
            acl = m.Ldif.Acl(
                name=acl_name,
                target=m.Ldif.AclTarget.model_validate({
                    "target_dn": target_dn,
                    "attributes": target_attributes,
                }),
                subject=m.Ldif.AclSubject(
                    subject_type=c.Ldif.AclSubjectType.USER,
                    subject_value=self._parse_userdn_subject(content),
                ),
                permissions=permissions_data,
                metadata=metadata,
                raw_acl=acl_line,
            )
            return r[p.Ldif.Acl].ok(acl)

        @staticmethod
        def _parse_target_attributes(content: str) -> t.MutableSequenceOf[str]:
            """Parse targetattr clause from 389 DS ACI content."""
            target_attr_match = (
                FlextLdifServersDs389.Constants.ACL_TARGETATTR_RE.search(content)
            )
            if not target_attr_match:
                return []
            attr_string = target_attr_match.group(1).replace(
                FlextLdifServersDs389.Constants.ACL_TARGETATTR_SEPARATOR,
                FlextLdifServersDs389.Constants.ACL_TARGETATTR_SPACE_REPLACEMENT,
            )
            return [attr.strip() for attr in attr_string.split() if attr.strip()]

        @staticmethod
        def _parse_target_dn(content: str) -> str:
            """Parse target DN clause from 389 DS ACI content."""
            target_match = FlextLdifServersDs389.Constants.ACL_TARGET_RE.search(content)
            if not target_match:
                return "*"
            target_clause = str(target_match.group(1))
            dn_prefix = FlextLdifServersDs389.Constants.ACL_TARGET_DN_PREFIX
            if target_clause.lower().startswith(dn_prefix):
                return target_clause[len(dn_prefix) :]
            return target_clause

        @staticmethod
        def _parse_userdn_subject(content: str) -> str:
            """Parse userdn subject from 389 DS ACI content."""
            userdn_matches = FlextLdifServersDs389.Constants.ACL_USERDN_RE.findall(
                content
            )
            if userdn_matches:
                return str(userdn_matches[0])
            anonymous_subject: str = (
                FlextLdifServersDs389.Constants.ACL_ANONYMOUS_SUBJECT
            )
            return anonymous_subject

        def _write_ds389_acl(self, acl_data: p.Ldif.Acl) -> p.Result[str]:
            """Write 389 DS ACL content."""
            if acl_data.raw_acl:
                acl_str = (
                    f"{FlextLdifServersDs389.Constants.ACL_ACI_PREFIX} "
                    f"{acl_data.raw_acl}"
                )
                return r[str].ok(acl_str)
            acl_name = acl_data.name or FlextLdifServersDs389.Constants.ACL_DEFAULT_NAME
            permissions = self._extract_acl_permissions(acl_data.permissions)
            targetattr = self._resolve_acl_targetattr(acl_data.target)
            userdn = self._resolve_acl_userdn(acl_data.subject)
            return self._build_acl_string(acl_name, permissions, targetattr, userdn)

    class Entry(FlextLdifServersRfc.Entry):
        """Entry servers for 389 Directory Server."""

        @override
        def can_handle(
            self, entry_dn: str, attributes: t.MutableStrSequenceMapping
        ) -> bool:
            """Detect 389 DS-specific entries."""
            if not entry_dn:
                return False
            dn_lower = entry_dn.lower()
            if any(
                marker in dn_lower
                for marker in FlextLdifServersDs389.Constants.DETECTION_DN_MARKERS
            ):
                return True
            normalized_attrs = {
                name.lower(): value for name, value in attributes.items()
            }
            if any(
                attr.startswith(
                    tuple(FlextLdifServersDs389.Constants.DETECTION_ATTRIBUTE_PREFIXES)
                )
                for attr in normalized_attrs
            ):
                return True
            objectclass_key = c.Ldif.DictKeys.OBJECTCLASS.lower()
            object_classes_raw = normalized_attrs.get(objectclass_key, [])
            object_classes: t.MutableSequenceOf[str] = object_classes_raw
            return any(
                oc.lower()
                in FlextLdifServersDs389.Constants.DETECTION_OBJECTCLASS_NAMES
                for oc in object_classes
            )

        def process_entry(self, entry: p.Ldif.Entry) -> p.Result[p.Ldif.Entry]:
            """Normalise 389 DS entries and attach metadata."""
            try:
                return self._process_ds389_entry(entry)
            except c.EXC_BASIC_TYPE as exc:
                return r[p.Ldif.Entry].fail(
                    FlextLdifServersDs389.Constants.ERROR_ENTRY_PROCESSING_FAILED.format(
                        exc=exc
                    )
                )

        def _process_ds389_entry(self, entry: p.Ldif.Entry) -> p.Result[p.Ldif.Entry]:
            """Normalize a 389 DS entry and attach metadata."""
            if not entry.attributes or not entry.dn:
                return r[p.Ldif.Entry].ok(entry)
            attributes: t.MutableStrSequenceMapping = {**entry.attributes.attributes}
            dn_lower = entry.dn.value.lower()
            metadata = entry.metadata or m.Ldif.ServerMetadata(
                server_type=c.Ldif.ServerTypes.DS389
            )
            metadata.extensions[c.Ldif.ServerMetadataKeys.IS_CONFIG_ENTRY] = any(
                marker in dn_lower
                for marker in FlextLdifServersDs389.Constants.DETECTION_DN_MARKERS
            )
            processed_entry = m.Ldif.Entry(
                dn=entry.dn,
                attributes=m.Ldif.Attributes.model_validate({"attributes": attributes}),
                metadata=metadata,
            )
            return r[p.Ldif.Entry].ok(processed_entry)


__all__: list[str] = ["FlextLdifServersDs389"]
