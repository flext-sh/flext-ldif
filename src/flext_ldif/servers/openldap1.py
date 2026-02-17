"""OpenLDAP 1.x Legacy Quirks - Complete Implementation."""

from __future__ import annotations

import re
from typing import ClassVar

from flext_core import r

from flext_ldif._models.domain import FlextLdifModelsDomains
from flext_ldif.constants import c
from flext_ldif.models import m
from flext_ldif.servers.rfc import FlextLdifServersRfc


class FlextLdifServersOpenldap1(FlextLdifServersRfc):
    """OpenLDAP 1.x Legacy Quirks - Complete Implementation."""

    class Constants(FlextLdifServersRfc.Constants):
        """Standardized constants for OpenLDAP 1.x quirk."""

        SERVER_TYPE: ClassVar[str] = "openldap1"
        PRIORITY: ClassVar[int] = 10

        DEFAULT_PORT: ClassVar[int] = 389
        DEFAULT_SSL_PORT: ClassVar[int] = 636
        DEFAULT_PAGE_SIZE: ClassVar[int] = 1000

        CANONICAL_NAME: ClassVar[str] = "openldap1"
        ALIASES: ClassVar[frozenset[str]] = frozenset(["openldap1"])
        CAN_NORMALIZE_FROM: ClassVar[frozenset[str]] = frozenset(["openldap1"])
        CAN_DENORMALIZE_TO: ClassVar[frozenset[str]] = frozenset(["openldap1", "rfc"])

        ACL_FORMAT: ClassVar[str] = "access"
        ACL_ATTRIBUTE_NAME: ClassVar[str] = "access"

        ACL_PERMISSION_AUTH: ClassVar[str] = "auth"
        SUPPORTED_PERMISSIONS: ClassVar[frozenset[str]] = (
            FlextLdifServersRfc.Constants.SUPPORTED_PERMISSIONS
            | frozenset([ACL_PERMISSION_AUTH])
        )

        OPENLDAP_1_ATTRIBUTES: ClassVar[frozenset[str]] = frozenset(
            [
                "attributetype",
                c.Ldif.DictKeys.OBJECTCLASS.lower(),
                "access",
                "rootdn",
                "rootpw",
                "suffix",
            ],
        )

        DETECTION_OID_PATTERN: ClassVar[str] = r"1\.3\.6\.1\.4\.1\.4203\."
        OBJECTCLASS_KEYWORD: ClassVar[str] = "objectclass"
        DETECTION_PATTERN: ClassVar[str] = r"\b(attributetype|objectclass|access)\b"
        DETECTION_ATTRIBUTES: ClassVar[frozenset[str]] = frozenset(
            [
                "attributetype",
                "objectclass",
                "access",
                "rootdn",
                "rootpw",
                "suffix",
            ],
        )
        DETECTION_WEIGHT: ClassVar[int] = 6
        DETECTION_ATTRIBUTE_PREFIXES: ClassVar[frozenset[str]] = frozenset(
            [
                "attributetype",
                "objectclass",
                "access",
                "rootdn",
            ],
        )
        DETECTION_OBJECTCLASS_NAMES: ClassVar[frozenset[str]] = frozenset(
            [
                "top",
                "domain",
                "organizationalunit",
                "person",
                "groupofnames",
            ],
        )
        DETECTION_DN_MARKERS: ClassVar[frozenset[str]] = frozenset(
            [
                "dc=",
                "ou=",
            ],
        )

        ACL_TARGET_DN_PREFIX: ClassVar[str] = "dn="
        ACL_TARGET_ATTRS_PREFIX: ClassVar[str] = "attrs="

        SCHEMA_OPENLDAP1_ATTRIBUTE_PATTERN: ClassVar[str] = r"^\s*attributetype\s+"
        SCHEMA_OPENLDAP1_OBJECTCLASS_PATTERN: ClassVar[str] = r"^\s*objectclass\s+"

        ACL_BY_PATTERN: ClassVar[str] = r"by\s+([^\s]+)\s+([^\s]+)"
        ACL_ACCESS_TO_PATTERN: ClassVar[str] = r"^\s*access\s+to\s+"

        ACL_TO_BY_PATTERN: ClassVar[str] = r"^to\s+(.+?)\s+by\s+"
        ACL_SUBJECT_TYPE_USERDN: ClassVar[str] = "userdn"

        ACL_OPS_SEPARATOR: ClassVar[str] = ","

    class Schema(FlextLdifServersRfc.Schema):
        """OpenLDAP 1.x schema quirk."""

        def can_handle_attribute(
            self,
            attr_definition: str | m.Ldif.SchemaAttribute,
        ) -> bool:
            """Check if this is an OpenLDAP 1.x attribute."""
            if isinstance(attr_definition, str):
                if not re.match(
                    FlextLdifServersOpenldap1.Constants.SCHEMA_OPENLDAP1_ATTRIBUTE_PATTERN,
                    attr_definition,
                    re.IGNORECASE,
                ):
                    return False

                has_olc = "olc" in attr_definition.lower()
                return not has_olc

            has_olc = (
                "olc" in attr_definition.oid.lower() if attr_definition.oid else False
            )
            if not has_olc and attr_definition.name:
                has_olc = "olc" in attr_definition.name.lower()
            return not has_olc

        def can_handle_objectclass(
            self,
            oc_definition: str | m.Ldif.SchemaObjectClass,
        ) -> bool:
            """Check if this is an OpenLDAP 1.x objectClass."""
            if isinstance(oc_definition, str):
                if not re.match(
                    FlextLdifServersOpenldap1.Constants.SCHEMA_OPENLDAP1_OBJECTCLASS_PATTERN,
                    oc_definition,
                    re.IGNORECASE,
                ):
                    return False

                has_olc = "olc" in oc_definition.lower()
                return not has_olc

            has_olc = "olc" in oc_definition.oid.lower() if oc_definition.oid else False
            if not has_olc and oc_definition.name:
                has_olc = "olc" in oc_definition.name.lower()
            return not has_olc

        def _parse_attribute(
            self,
            attr_definition: str,
        ) -> r[m.Ldif.SchemaAttribute]:
            """Parse attribute definition, strip OpenLDAP1 prefix, and add metadata."""
            stripped = re.sub(
                FlextLdifServersOpenldap1.Constants.SCHEMA_OPENLDAP1_ATTRIBUTE_PATTERN,
                "",
                attr_definition,
                flags=re.IGNORECASE,
            ).strip()

            result = super()._parse_attribute(stripped)
            if result.is_success:
                attr_data = result.value
                metadata = m.Ldif.QuirkMetadata.create_for("openldap1")
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
            """Parse objectClass definition and add OpenLDAP1 metadata."""
            stripped = re.sub(
                FlextLdifServersOpenldap1.Constants.SCHEMA_OPENLDAP1_OBJECTCLASS_PATTERN,
                "",
                oc_definition,
            ).strip()
            result = super()._parse_objectclass(stripped)
            if result.is_success:
                oc_data = result.value
                metadata = m.Ldif.QuirkMetadata.create_for("openldap1")
                return r[m.Ldif.SchemaObjectClass].ok(
                    oc_data.model_copy(
                        update={"metadata": metadata},
                    ),
                )
            return result

        def _write_attribute(
            self,
            attr_data: m.Ldif.SchemaAttribute,
        ) -> r[str]:
            """Write attribute data to RFC-compliant string format."""
            try:
                oid = attr_data.oid
                name = attr_data.name
                desc = attr_data.desc
                syntax = attr_data.syntax
                equality = attr_data.equality
                single_value = attr_data.single_value or False

                attr_str = f"attributetype ( {oid}"
                if name:
                    attr_str += f" NAME '{name}'"
                if desc:
                    attr_str += f" DESC '{desc}'"
                if syntax:
                    attr_str += f" SYNTAX {syntax}"
                if equality:
                    attr_str += f" EQUALITY {equality}"
                if single_value:
                    attr_str += " SINGLE-VALUE"
                attr_str += " )"

                return r[str].ok(attr_str)

            except Exception as e:
                return r[str].fail(
                    f"OpenLDAP 1.x attribute write failed: {e}",
                )

        def _write_objectclass(
            self,
            oc_data: m.Ldif.SchemaObjectClass,
        ) -> r[str]:
            """Write objectClass data to RFC-compliant string format."""
            try:
                oid = oc_data.oid
                name = oc_data.name
                desc = oc_data.desc
                sup = oc_data.sup

                kind: str
                kind = oc_data.kind or "STRUCTURAL"
                must: list[str]
                must = oc_data.must if oc_data.must is not None else []
                may: list[str]
                may = oc_data.may if oc_data.may is not None else []

                oc_str = f"objectclass ( {oid}"
                if name:
                    oc_str += f" NAME '{name}'"
                if desc:
                    oc_str += f" DESC '{desc}'"
                if sup:
                    oc_str += f" SUP {sup}"
                oc_str += f" {kind}"
                if must and isinstance(must, (list, tuple)):
                    if not isinstance(must, list):
                        msg = f"Expected list, got {type(must)}"
                        raise TypeError(msg)
                    must_list_str: list[str] = [str(item) for item in must]
                    must_attrs = " $ ".join(must_list_str)
                    oc_str += f" MUST ( {must_attrs} )"
                if may and isinstance(may, (list, tuple)):
                    if not isinstance(may, list):
                        msg = f"Expected list, got {type(may)}"
                        raise TypeError(msg)
                    may_list_str: list[str] = [str(item) for item in may]
                    may_attrs = " $ ".join(may_list_str)
                    oc_str += f" MAY ( {may_attrs} )"
                oc_str += " )"

                return r[str].ok(oc_str)

            except Exception as e:
                return r[str].fail(
                    f"OpenLDAP 1.x objectClass write failed: {e}",
                )

    class Acl(FlextLdifServersRfc.Acl):
        """OpenLDAP 1.x ACL quirk (nested)."""

        def can_handle(self, acl_line: str | m.Ldif.Acl) -> bool:
            """Check if this is an OpenLDAP 1.x ACL (public method)."""
            if isinstance(acl_line, str):
                return self.can_handle_acl(acl_line)

            if isinstance(acl_line, m.Ldif.Acl):
                return self.can_handle_acl(acl_line)

            if isinstance(acl_line, object):
                raw_acl = getattr(acl_line, "raw_acl", None)
                if isinstance(raw_acl, str):
                    return self.can_handle_acl(raw_acl)
            return False

        def can_handle_acl(self, acl_line: str | m.Ldif.Acl) -> bool:
            """Check if this is an OpenLDAP 1.x ACL."""
            if isinstance(acl_line, str):
                return bool(
                    re.match(
                        FlextLdifServersOpenldap1.Constants.ACL_ACCESS_TO_PATTERN,
                        acl_line,
                        re.IGNORECASE,
                    ),
                )
            if not isinstance(acl_line, m.Ldif.Acl) or not acl_line.raw_acl:
                return False

            return bool(
                re.match(
                    FlextLdifServersOpenldap1.Constants.ACL_ACCESS_TO_PATTERN,
                    acl_line.raw_acl,
                    re.IGNORECASE,
                ),
            )

        def _parse_acl(self, acl_line: str) -> r[m.Ldif.Acl]:
            """Parse OpenLDAP 1.x ACL definition."""
            try:
                acl_content = acl_line
                if acl_line.lower().startswith(
                    FlextLdifServersOpenldap1.Constants.ACL_ATTRIBUTE_NAME,
                ):
                    acl_content = acl_line[
                        len(FlextLdifServersOpenldap1.Constants.ACL_ATTRIBUTE_NAME) :
                    ].strip()

                to_match = re.match(
                    FlextLdifServersOpenldap1.Constants.ACL_TO_BY_PATTERN,
                    acl_content,
                    re.IGNORECASE,
                )
                if not to_match:
                    return r[m.Ldif.Acl].fail(
                        "Invalid OpenLDAP 1.x ACL format: missing 'to' clause",
                    )

                what = to_match.group(1).strip()

                by_matches = list(
                    re.finditer(
                        FlextLdifServersOpenldap1.Constants.ACL_BY_PATTERN,
                        acl_content,
                        re.IGNORECASE,
                    ),
                )

                first_who = by_matches[0].group(1) if by_matches else "*"
                first_access = by_matches[0].group(2).lower() if by_matches else "none"

                target_dn = ""
                target_attrs: list[str] = []

                dn_prefix = FlextLdifServersOpenldap1.Constants.ACL_TARGET_DN_PREFIX
                attrs_prefix = (
                    FlextLdifServersOpenldap1.Constants.ACL_TARGET_ATTRS_PREFIX
                )
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

                read_perm = FlextLdifServersRfc.Constants.PERMISSION_READ
                write_perm = FlextLdifServersRfc.Constants.PERMISSION_WRITE
                auth_perm = FlextLdifServersOpenldap1.Constants.ACL_PERMISSION_AUTH
                permissions = m.Ldif.AclPermissions(
                    read=read_perm in first_access or write_perm in first_access,
                    write=write_perm in first_access,
                    add=write_perm in first_access,
                    delete=write_perm in first_access,
                    search=read_perm in first_access or auth_perm in first_access,
                    compare=read_perm in first_access or auth_perm in first_access,
                )

                first_who_lower = first_who.lower().strip()
                subject_type: c.Ldif.LiteralTypes.AclSubjectTypeLiteral
                if first_who_lower == "self":
                    subject_type = "self"
                elif first_who_lower in {"*", "all"}:
                    subject_type = "all"
                elif first_who_lower == "anonymous":
                    subject_type = "anonymous"
                elif first_who_lower == "authenticated":
                    subject_type = "authenticated"
                else:
                    subject_type = "user"

                acl_extensions = m.Ldif.DynamicMetadata.model_construct(
                    _fields_set={"original_format"},
                    original_format=acl_line,
                )
                acl = m.Ldif.Acl(
                    name=FlextLdifServersOpenldap1.Constants.ACL_ATTRIBUTE_NAME,
                    target=m.Ldif.AclTarget(
                        target_dn=target_dn,
                        attributes=target_attrs,
                    ),
                    subject=m.Ldif.AclSubject(
                        subject_type=subject_type,
                        subject_value=first_who,
                    ),
                    permissions=permissions,
                    metadata=m.Ldif.QuirkMetadata.create_for(
                        quirk_type=self._get_server_type(),
                        extensions=acl_extensions,
                    ),
                    raw_acl=acl_line,
                )

                return r[m.Ldif.Acl].ok(acl)

            except Exception as e:
                return r[m.Ldif.Acl].fail(
                    f"OpenLDAP 1.x ACL parsing failed: {e}",
                )

        def _write_acl(self, acl_data: FlextLdifModelsDomains.Acl) -> r[str]:
            """Write ACL data to RFC-compliant string format."""
            try:
                if acl_data.raw_acl:
                    return r[str].ok(acl_data.raw_acl)

                what = acl_data.target.target_dn if acl_data.target else "*"
                who = acl_data.subject.subject_value if acl_data.subject else "*"

                acl_str = f"access to {what} by {who}"
                if acl_data.permissions:
                    perms = []

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

            except Exception as e:
                return r[str].fail(f"OpenLDAP 1.x ACL write failed: {e}")

    class Entry(FlextLdifServersRfc.Entry):
        """OpenLDAP 1.x entry quirk (nested)."""

        def can_handle(
            self,
            entry_dn: str,
            attributes: dict[str, list[str]],
        ) -> bool:
            """Check if this quirk should handle the entry."""
            if not entry_dn:
                return False

            config_marker = "cn=config"
            is_config_dn = config_marker in entry_dn.lower()

            has_olc_attrs = any(
                attr_name.lower().startswith("olc") for attr_name in attributes
            )

            return not is_config_dn and not has_olc_attrs

        def process_entry(
            self,
            entry: m.Ldif.Entry,
        ) -> r[m.Ldif.Entry]:
            """Process entry for OpenLDAP 1.x format."""
            try:
                metadata = entry.metadata or m.Ldif.QuirkMetadata(
                    quirk_type=c.Ldif.ServerTypes.OPENLDAP1,
                )
                metadata.extensions[
                    c.Ldif.Domain.QuirkMetadataKeys.IS_TRADITIONAL_DIT
                ] = True

                processed_entry = m.Ldif.Entry(
                    dn=entry.dn,
                    attributes=entry.attributes,
                    metadata=metadata,
                )

                return r[m.Ldif.Entry].ok(
                    processed_entry,
                )

            except Exception as e:
                return r[m.Ldif.Entry].fail(
                    f"OpenLDAP 1.x entry processing failed: {e}",
                )
