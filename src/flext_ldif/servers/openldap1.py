"""OpenLDAP 1.x Legacy Servers - Complete Implementation."""

from __future__ import annotations

import re
from typing import ClassVar, override

from flext_ldif import FlextLdifServersRfc, c, m, p, r, t


class FlextLdifServersOpenldap1(FlextLdifServersRfc):
    """OpenLDAP 1.x Legacy Servers - Complete Implementation."""

    class Constants(FlextLdifServersRfc.Constants):
        """Standardized constants for OpenLDAP 1.x server."""

        SERVER_TYPE: ClassVar[str] = c.Ldif.ServerTypes.OPENLDAP1
        PRIORITY: ClassVar[int] = 10
        DEFAULT_PORT: ClassVar[int] = c.LDAP_PORT
        DEFAULT_SSL_PORT: ClassVar[int] = c.LDAPS_PORT
        DEFAULT_PAGE_SIZE: ClassVar[int] = 1000
        CANONICAL_NAME: ClassVar[str] = c.Ldif.ServerTypes.OPENLDAP1
        ALIASES: ClassVar[frozenset[str]] = frozenset({
            c.Ldif.ServerTypes.OPENLDAP1,
            *(
                alias
                for alias, server_type in c.Ldif.SERVER_TYPE_ALIASES.items()
                if server_type == c.Ldif.ServerTypes.OPENLDAP1
            ),
        })
        CAN_NORMALIZE_FROM: ClassVar[frozenset[str]] = frozenset({
            c.Ldif.ServerTypes.OPENLDAP1,
        })
        CAN_DENORMALIZE_TO: ClassVar[frozenset[str]] = frozenset({
            c.Ldif.ServerTypes.OPENLDAP1,
            c.Ldif.ServerTypes.RFC,
        })
        ACL_FORMAT: ClassVar[str] = "access"
        ACL_ATTRIBUTE_NAME: ClassVar[str] = "access"
        ACL_PERMISSION_AUTH: ClassVar[str] = "auth"
        SUPPORTED_PERMISSIONS: ClassVar[frozenset[str]] = (
            FlextLdifServersRfc.Constants.SUPPORTED_PERMISSIONS
            | frozenset([ACL_PERMISSION_AUTH])
        )
        OPENLDAP_1_ATTRIBUTES: ClassVar[frozenset[str]] = frozenset([
            "attributetype",
            c.Ldif.DictKeys.OBJECTCLASS.lower(),
            "access",
            "rootdn",
            "rootpw",
            "suffix",
        ])
        DETECTION_OID_PATTERN: ClassVar[str] = "1\\.3\\.6\\.1\\.4\\.1\\.4203\\."
        OBJECTCLASS_KEYWORD: ClassVar[str] = "objectclass"
        DETECTION_PATTERN: ClassVar[str] = "\\b(attributetype|objectclass|access)\\b"
        DETECTION_ATTRIBUTES: ClassVar[frozenset[str]] = frozenset([
            "attributetype",
            "objectclass",
            "access",
            "rootdn",
            "rootpw",
            "suffix",
        ])
        DETECTION_WEIGHT: ClassVar[int] = 6
        DETECTION_ATTRIBUTE_PREFIXES: ClassVar[frozenset[str]] = frozenset([
            "attributetype",
            "objectclass",
            "access",
            "rootdn",
        ])
        DETECTION_OBJECTCLASS_NAMES: ClassVar[frozenset[str]] = frozenset([
            "top",
            "domain",
            "organizationalunit",
            "person",
            "groupofnames",
        ])
        DETECTION_DN_MARKERS: ClassVar[frozenset[str]] = frozenset(["dc=", "ou="])
        ACL_TARGET_DN_PREFIX: ClassVar[str] = "dn="
        ACL_TARGET_ATTRS_PREFIX: ClassVar[str] = "attrs="
        SCHEMA_OPENLDAP1_ATTRIBUTE_PATTERN: ClassVar[str] = "^\\s*attributetype\\s+"
        SCHEMA_OPENLDAP1_ATTRIBUTE_RE: ClassVar[t.Ldif.RegexPattern] = re.compile(
            SCHEMA_OPENLDAP1_ATTRIBUTE_PATTERN, re.IGNORECASE
        )
        SCHEMA_OPENLDAP1_OBJECTCLASS_PATTERN: ClassVar[str] = "^\\s*objectclass\\s+"
        SCHEMA_OPENLDAP1_OBJECTCLASS_RE: ClassVar[t.Ldif.RegexPattern] = re.compile(
            SCHEMA_OPENLDAP1_OBJECTCLASS_PATTERN, re.IGNORECASE
        )
        ACL_BY_PATTERN: ClassVar[str] = "by\\s+([^\\s]+)\\s+([^\\s]+)"
        ACL_BY_RE: ClassVar[t.Ldif.RegexPattern] = re.compile(
            ACL_BY_PATTERN,
            re.IGNORECASE,
        )
        ACL_ACCESS_TO_PATTERN: ClassVar[str] = "^\\s*access\\s+to\\s+"
        ACL_ACCESS_TO_RE: ClassVar[t.Ldif.RegexPattern] = re.compile(
            ACL_ACCESS_TO_PATTERN,
            re.IGNORECASE,
        )
        ACL_TO_BY_PATTERN: ClassVar[str] = "^to\\s+(.+?)\\s+by\\s+"
        ACL_TO_BY_RE: ClassVar[t.Ldif.RegexPattern] = re.compile(
            ACL_TO_BY_PATTERN,
            re.IGNORECASE,
        )
        ACL_SUBJECT_TYPE_USERDN: ClassVar[str] = "userdn"
        ACL_OPS_SEPARATOR: ClassVar[str] = ","

    class Schema(FlextLdifServersRfc.Schema):
        """OpenLDAP 1.x schema server."""

        @override
        def can_handle_attribute(
            self,
            attr_definition: str | m.Ldif.SchemaAttribute,
        ) -> bool:
            """Check if this is an OpenLDAP 1.x attribute."""
            if isinstance(attr_definition, str):
                if not FlextLdifServersOpenldap1.Constants.SCHEMA_OPENLDAP1_ATTRIBUTE_RE.match(
                    attr_definition
                ):
                    return False
                has_olc = "olc" in attr_definition.lower()
                return not has_olc
            has_olc = "olc" in attr_definition.oid.lower()
            if not has_olc:
                has_olc = "olc" in attr_definition.name.lower()
            return not has_olc

        @override
        def can_handle_objectclass(
            self,
            oc_definition: str | m.Ldif.SchemaObjectClass,
        ) -> bool:
            """Check if this is an OpenLDAP 1.x objectClass."""
            if isinstance(oc_definition, str):
                if not FlextLdifServersOpenldap1.Constants.SCHEMA_OPENLDAP1_OBJECTCLASS_RE.match(
                    oc_definition
                ):
                    return False
                has_olc = "olc" in oc_definition.lower()
                return not has_olc
            has_olc = "olc" in oc_definition.oid.lower()
            if not has_olc:
                has_olc = "olc" in oc_definition.name.lower()
            return not has_olc

        @override
        def _parse_attribute(
            self, attr_definition: str
        ) -> p.Result[m.Ldif.SchemaAttribute]:
            """Parse attribute definition, strip OpenLDAP1 prefix, and add metadata."""
            stripped = (
                FlextLdifServersOpenldap1.Constants.SCHEMA_OPENLDAP1_ATTRIBUTE_RE.sub(
                    "", attr_definition
                ).strip()
            )
            result = super()._parse_attribute(stripped)
            if result.success:
                attr_data = result.value
                metadata = m.Ldif.ServerMetadata.create_for(
                    FlextLdifServersOpenldap1.Constants.SERVER_TYPE,
                )
                return r[m.Ldif.SchemaAttribute].ok(
                    attr_data.model_copy(update={"metadata": metadata}),
                )
            return result

        @override
        def _parse_objectclass(
            self, oc_definition: str
        ) -> p.Result[m.Ldif.SchemaObjectClass]:
            """Parse objectClass definition and add OpenLDAP1 metadata."""
            stripped = (
                FlextLdifServersOpenldap1.Constants.SCHEMA_OPENLDAP1_OBJECTCLASS_RE.sub(
                    "", oc_definition
                ).strip()
            )
            result = super()._parse_objectclass(stripped)
            if result.success:
                oc_data = result.value
                metadata = m.Ldif.ServerMetadata.create_for(
                    FlextLdifServersOpenldap1.Constants.SERVER_TYPE,
                )
                return r[m.Ldif.SchemaObjectClass].ok(
                    oc_data.model_copy(update={"metadata": metadata}),
                )
            return result

        @override
        def _write_attribute(self, attr_data: m.Ldif.SchemaAttribute) -> p.Result[str]:
            """Write attribute data to RFC-compliant string format."""
            try:
                return self._write_openldap1_attribute(attr_data)
            except c.Ldif.EXC_LDIF_PARSE as e:
                return r[str].fail_op("OpenLDAP 1.x attribute write", e)

        @override
        def _write_objectclass(
            self, oc_data: m.Ldif.SchemaObjectClass
        ) -> p.Result[str]:
            """Write objectClass data to RFC-compliant string format."""
            try:
                return self._write_openldap1_objectclass(oc_data)
            except c.Ldif.EXC_LDIF_PARSE as e:
                return r[str].fail_op("OpenLDAP 1.x objectClass write", e)

        @staticmethod
        def _write_openldap1_attribute(
            attr_data: m.Ldif.SchemaAttribute,
        ) -> p.Result[str]:
            """Write OpenLDAP 1.x attribute definition."""
            attr_str = f"attributetype ( {attr_data.oid}"
            if attr_data.name:
                attr_str += f" NAME '{attr_data.name}'"
            if attr_data.desc:
                attr_str += f" DESC '{attr_data.desc}'"
            if attr_data.syntax:
                attr_str += f" SYNTAX {attr_data.syntax}"
            if attr_data.equality:
                attr_str += f" EQUALITY {attr_data.equality}"
            if attr_data.single_value or False:
                attr_str += " SINGLE-VALUE"
            attr_str += " )"
            return r[str].ok(attr_str)

        @staticmethod
        def _write_openldap1_objectclass(
            oc_data: m.Ldif.SchemaObjectClass,
        ) -> p.Result[str]:
            """Write OpenLDAP 1.x objectClass definition."""
            kind = oc_data.kind or "STRUCTURAL"
            must = oc_data.must if oc_data.must is not None else []
            may = oc_data.may if oc_data.may is not None else []
            oc_str = f"objectclass ( {oc_data.oid}"
            if oc_data.name:
                oc_str += f" NAME '{oc_data.name}'"
            if oc_data.desc:
                oc_str += f" DESC '{oc_data.desc}'"
            if oc_data.sup:
                oc_str += f" SUP {oc_data.sup}"
            oc_str += f" {kind}"
            if must:
                must_attrs = " $ ".join(list(must))
                oc_str += f" MUST ( {must_attrs} )"
            if may:
                may_attrs = " $ ".join(list(may))
                oc_str += f" MAY ( {may_attrs} )"
            oc_str += " )"
            return r[str].ok(oc_str)

    class Acl(FlextLdifServersRfc.Acl):
        """OpenLDAP 1.x ACL server (nested)."""

        @override
        def can_handle(self, acl_line: str | m.Ldif.Acl) -> bool:
            """Check if this is an OpenLDAP 1.x ACL (public method)."""
            return self.can_handle_acl(acl_line)

        @override
        def can_handle_acl(self, acl_line: str | m.Ldif.Acl) -> bool:
            """Check if this is an OpenLDAP 1.x ACL."""
            if isinstance(acl_line, str):
                return bool(
                    FlextLdifServersOpenldap1.Constants.ACL_ACCESS_TO_RE.match(acl_line)
                )
            raw_acl = getattr(acl_line, "raw_acl", None)
            if not isinstance(raw_acl, str) or not raw_acl:
                return False
            return bool(
                FlextLdifServersOpenldap1.Constants.ACL_ACCESS_TO_RE.match(raw_acl)
            )

        @override
        def _parse_acl(self, acl_line: str) -> p.Result[m.Ldif.Acl]:
            """Parse OpenLDAP 1.x ACL definition."""
            try:
                return self._parse_openldap1_acl(acl_line)
            except c.Ldif.EXC_LDIF_PARSE as e:
                return r[m.Ldif.Acl].fail_op("OpenLDAP 1.x ACL parsing", e)

        @override
        def _write_acl(self, acl_data: m.Ldif.Acl) -> p.Result[str]:
            """Write ACL data to RFC-compliant string format."""
            try:
                return self._write_openldap1_acl(acl_data)
            except c.Ldif.EXC_LDIF_PARSE as e:
                return r[str].fail_op("OpenLDAP 1.x ACL write", e)

        def _parse_openldap1_acl(self, acl_line: str) -> p.Result[m.Ldif.Acl]:
            """Parse OpenLDAP 1.x ACL content."""
            acl_content = self._strip_openldap1_acl_prefix(acl_line)
            to_match = FlextLdifServersOpenldap1.Constants.ACL_TO_BY_RE.match(
                acl_content
            )
            if not to_match:
                return r[m.Ldif.Acl].fail(
                    "Invalid OpenLDAP 1.x ACL format: missing 'to' clause",
                )
            what = to_match.group(1).strip()
            by_matches = list(
                FlextLdifServersOpenldap1.Constants.ACL_BY_RE.finditer(acl_content)
            )
            first_who = by_matches[0].group(1) if by_matches else "*"
            first_access = by_matches[0].group(2).lower() if by_matches else "none"
            target_dn, target_attrs = self._parse_openldap1_target(what)
            acl_extensions = m.Ldif.DynamicMetadata.model_construct(
                _fields_set={"original_format"},
                original_format=acl_line,
            )
            acl = m.Ldif.Acl(
                name=FlextLdifServersOpenldap1.Constants.ACL_ATTRIBUTE_NAME,
                target=m.Ldif.AclTarget.model_validate({
                    "target_dn": target_dn,
                    "attributes": target_attrs,
                }),
                subject=m.Ldif.AclSubject(
                    subject_type=self._openldap1_subject_type(first_who),
                    subject_value=first_who,
                ),
                permissions=self._openldap1_permissions(first_access),
                metadata=m.Ldif.ServerMetadata.create_for(
                    server_type=self._get_server_type(),
                    extensions=acl_extensions,
                ),
                raw_acl=acl_line,
            )
            return r[m.Ldif.Acl].ok(acl)

        @staticmethod
        def _strip_openldap1_acl_prefix(acl_line: str) -> str:
            """Remove OpenLDAP 1.x ACL attribute prefix."""
            if acl_line.lower().startswith(
                FlextLdifServersOpenldap1.Constants.ACL_ATTRIBUTE_NAME,
            ):
                return acl_line[
                    len(FlextLdifServersOpenldap1.Constants.ACL_ATTRIBUTE_NAME) :
                ].strip()
            return acl_line

        @staticmethod
        def _parse_openldap1_target(
            what: str,
        ) -> t.StrPair | tuple[str, t.MutableSequenceOf[str]]:
            """Parse OpenLDAP 1.x target DN and attribute list."""
            target_dn = ""
            target_attrs: t.MutableSequenceOf[str] = []
            dn_prefix = FlextLdifServersOpenldap1.Constants.ACL_TARGET_DN_PREFIX
            attrs_prefix = FlextLdifServersOpenldap1.Constants.ACL_TARGET_ATTRS_PREFIX
            if what.lower().startswith(dn_prefix):
                target_dn = what[len(dn_prefix) :].strip().strip('"')
            elif what.lower().startswith(attrs_prefix):
                attrs_str = what[len(attrs_prefix) :].strip()
                target_attrs = [
                    a.strip()
                    for a in attrs_str.split(
                        FlextLdifServersOpenldap1.Constants.ACL_OPS_SEPARATOR,
                    )
                ]
            return (target_dn, target_attrs)

        @staticmethod
        def _openldap1_permissions(first_access: str) -> m.Ldif.AclPermissions:
            """Build permissions from first OpenLDAP 1.x access token."""
            read_perm = FlextLdifServersRfc.Constants.PERMISSION_READ
            write_perm = FlextLdifServersRfc.Constants.PERMISSION_WRITE
            auth_perm = FlextLdifServersOpenldap1.Constants.ACL_PERMISSION_AUTH
            return m.Ldif.AclPermissions(
                read=read_perm in first_access or write_perm in first_access,
                write=write_perm in first_access,
                add=write_perm in first_access,
                delete=write_perm in first_access,
                search=read_perm in first_access or auth_perm in first_access,
                compare=read_perm in first_access or auth_perm in first_access,
            )

        @staticmethod
        def _openldap1_subject_type(first_who: str) -> c.Ldif.AclSubjectType:
            """Resolve subject type from OpenLDAP 1.x who token."""
            first_who_lower = first_who.lower().strip()
            if first_who_lower == "self":
                return c.Ldif.AclSubjectType.SELF
            if first_who_lower in {"*", "all"}:
                return c.Ldif.AclSubjectType.ALL
            if first_who_lower == "anonymous":
                return c.Ldif.AclSubjectType.ANONYMOUS
            if first_who_lower == "authenticated":
                return c.Ldif.AclSubjectType.AUTHENTICATED
            return c.Ldif.AclSubjectType.USER

        @staticmethod
        def _write_openldap1_acl(acl_data: m.Ldif.Acl) -> p.Result[str]:
            """Write OpenLDAP 1.x ACL content."""
            if acl_data.raw_acl:
                return r[str].ok(acl_data.raw_acl)
            what = acl_data.target.target_dn if acl_data.target else "*"
            who = acl_data.subject.subject_value if acl_data.subject else "*"
            acl_str = f"access to {what} by {who}"
            if acl_data.permissions:
                perms: t.MutableSequenceOf[str] = []
                if acl_data.permissions.read:
                    perms.append(
                        FlextLdifServersOpenldap1.Constants.PERMISSION_READ,
                    )
                if acl_data.permissions.write:
                    perms.append(
                        FlextLdifServersOpenldap1.Constants.PERMISSION_WRITE,
                    )
                if perms:
                    acl_str += f" {','.join(perms)}"
            return r[str].ok(acl_str)

    class Entry(FlextLdifServersRfc.Entry):
        """OpenLDAP 1.x entry server (nested)."""

        @override
        def can_handle(
            self,
            entry_dn: str,
            attributes: t.MutableStrSequenceMapping,
        ) -> bool:
            """Check if this server should handle the entry."""
            if not entry_dn:
                return False
            config_marker = "cn=settings"
            is_config_dn = config_marker in entry_dn.lower()
            has_olc_attrs = any(
                attr_name.lower().startswith("olc") for attr_name in attributes
            )
            return not is_config_dn and (not has_olc_attrs)

        def process_entry(self, entry: m.Ldif.Entry) -> p.Result[m.Ldif.Entry]:
            """Process entry for OpenLDAP 1.x format."""
            try:
                metadata = entry.metadata or m.Ldif.ServerMetadata(
                    server_type=c.Ldif.ServerTypes.OPENLDAP1,
                )
                metadata.extensions[c.Ldif.ServerMetadataKeys.IS_TRADITIONAL_DIT] = True
                processed_entry = m.Ldif.Entry(
                    dn=entry.dn,
                    attributes=entry.attributes,
                    metadata=metadata,
                )
                return r[m.Ldif.Entry].ok(processed_entry)
            except c.Ldif.EXC_LDIF_PARSE as e:
                return r[m.Ldif.Entry].fail_op("OpenLDAP 1.x entry processing", e)
