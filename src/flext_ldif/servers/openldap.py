"""OpenLDAP 2.x Quirks - Complete Implementation."""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from typing import ClassVar

from flext_core import FlextLogger, FlextResult

from flext_ldif._models.domain import FlextLdifModelsDomains
from flext_ldif.constants import c
from flext_ldif.models import m
from flext_ldif.servers.rfc import FlextLdifServersRfc

logger = FlextLogger(__name__)


class FlextLdifServersOpenldap(FlextLdifServersRfc):
    """OpenLDAP 2.x Quirks - Complete Implementation."""

    class Constants(FlextLdifServersRfc.Constants):
        """Standardized constants for OpenLDAP 2.x quirk."""

        SERVER_TYPE: ClassVar[str] = "openldap2"
        PRIORITY: ClassVar[int] = 20

        DEFAULT_PORT: ClassVar[int] = 389
        DEFAULT_SSL_PORT: ClassVar[int] = 636
        DEFAULT_PAGE_SIZE: ClassVar[int] = 1000

        CANONICAL_NAME: ClassVar[str] = "openldap"
        ALIASES: ClassVar[frozenset[str]] = frozenset(["openldap", "openldap2"])
        CAN_NORMALIZE_FROM: ClassVar[frozenset[str]] = frozenset(["openldap"])
        CAN_DENORMALIZE_TO: ClassVar[frozenset[str]] = frozenset(["openldap", "rfc"])

        ACL_FORMAT: ClassVar[str] = "olcAccess"
        ACL_ATTRIBUTE_NAME: ClassVar[str] = "olcAccess"

        DETECTION_PATTERN: ClassVar[str] = r"\b(olc[A-Z][a-zA-Z]+|cn=config)\b"
        DETECTION_ATTRIBUTES: ClassVar[frozenset[str]] = frozenset(
            [
                "olcDatabase",
                "olcAccess",
                "olcOverlay",
                "olcModule",
            ],
        )
        DETECTION_WEIGHT: ClassVar[int] = 8

        OPENLDAP_2_ATTRIBUTES: ClassVar[frozenset[str]] = frozenset(
            [
                "olcAccess",
                "olcAttributeTypes",
                "olcObjectClasses",
                "olcDatabase",
                "olcBackend",
                "olcOverlay",
                "olcRootDN",
                "olcRootPW",
                "olcSuffix",
            ],
        )

        OPENLDAP_2_DN_PATTERNS: ClassVar[frozenset[str]] = frozenset(
            [
                "cn=config",
                "olcDatabase=",
                "olcOverlay=",
            ],
        )

        OPENLDAP_DN_PATTERNS: ClassVar[frozenset[str]] = frozenset(
            [
                "cn=",
                "ou=",
                "dc=",
                "o=",
                "l=",
                "st=",
                "c=",
                "uid=",
            ],
        )

        OLCDATABASE_PREFIX: ClassVar[str] = "olcDatabase="
        OLCOVERLAY_PREFIX: ClassVar[str] = "olcOverlay="

        ACL_SUBJECT_ANONYMOUS: ClassVar[str] = "*"
        ACL_SUBJECT_TYPE_DN: ClassVar[str] = "dn"
        ACL_SUBJECT_TYPE_GROUP: ClassVar[str] = "group"

        OPENLDAP_2_OBJECTCLASSES: ClassVar[frozenset[str]] = frozenset(
            [
                "olcDatabaseConfig",
                "olcBackendConfig",
                "olcOverlayConfig",
                "olcSchemaConfig",
            ],
        )

        OPERATIONAL_ATTRIBUTES: ClassVar[frozenset[str]] = (
            FlextLdifServersRfc.Constants.OPERATIONAL_ATTRIBUTES
            | frozenset(["entryUUID", "entryCSN", "contextCSN", "hasSubordinates"])
        )

        SUPPORTED_PERMISSIONS: ClassVar[frozenset[str]] = (
            FlextLdifServersRfc.Constants.SUPPORTED_PERMISSIONS | frozenset(["auth"])
        )

        ATTRIBUTE_FIELDS: ClassVar[frozenset[str]] = frozenset(["x_origin", "ordering"])

        OBJECTCLASS_REQUIREMENTS: ClassVar[Mapping[str, bool]] = {
            "requires_sup_for_auxiliary": True,
            "allows_multiple_sup": True,
            "requires_explicit_structural": False,
        }

        DETECTION_OID_PATTERN: ClassVar[str] = r"1\.3\.6\.1\.4\.1\.4203\."
        DETECTION_ATTRIBUTE_PREFIXES: ClassVar[frozenset[str]] = frozenset(
            [
                "olc",
                "structuralobjectclass",
            ],
        )
        DETECTION_OBJECTCLASS_NAMES: ClassVar[frozenset[str]] = frozenset(
            [
                "olcglobal",
                "olcdatabaseconfig",
                "olcldapconfig",
                "olcmdbconfig",
                "olcbdbconfig",
            ],
        )
        DETECTION_DN_MARKERS: ClassVar[frozenset[str]] = frozenset(
            [
                "cn=config",
                "cn=schema",
                "cn=monitor",
            ],
        )

        REQUIRED_CLASSES: ClassVar[frozenset[str]] = frozenset(
            [
                "top",
                "person",
                "organizationalPerson",
                "inetOrgPerson",
            ],
        )

        SCHEMA_OPENLDAP_OLC_PATTERN: ClassVar[str] = r"\bolc[A-Z][a-zA-Z]*\b"

        ACL_BY_PATTERN: ClassVar[str] = r"by\s+([^\s]+)\s+([^\s]+)"
        ACL_DEFAULT_NAME: ClassVar[str] = "access"

        ACL_INDEX_PATTERN: ClassVar[str] = r"^\{(\d+)\}\s*(.+)"
        ACL_TO_BY_PATTERN: ClassVar[str] = r"^to\s+(.+?)\s+by\s+"
        ACL_ATTRS_PATTERN: ClassVar[str] = r"attrs?\s*=\s*([^,\s]+(?:\s*,\s*[^,\s]+)*)"
        ACL_SUBJECT_TYPE_WHO: ClassVar[c.Ldif.LiteralTypes.AclSubjectTypeLiteral] = (
            "all"
        )

        ACL_INDEX_PREFIX_PATTERN: ClassVar[str] = r"^(\{\d+\})?\s*to\s+"
        ACL_START_PREFIX: ClassVar[str] = "to"

        ACL_ATTRS_SEPARATOR: ClassVar[str] = ","
        ACL_PREFIX_TO: ClassVar[str] = "to "
        ACL_PREFIX_BY: ClassVar[str] = "by "
        ACL_WILDCARD_TARGET: ClassVar[str] = "*"
        ACL_DEFAULT_ACCESS: ClassVar[str] = "none"
        ACL_OLCACCESS_PREFIX: ClassVar[str] = "olcAccess:"
        ACL_ERROR_MISSING_TO: ClassVar[str] = (
            "Invalid OpenLDAP ACL format: missing 'to' clause"
        )

    class Schema(FlextLdifServersRfc.Schema):
        """OpenLDAP 2.x schema quirk."""

        def can_handle_attribute(
            self,
            attr_definition: str | m.Ldif.SchemaAttribute,
        ) -> bool:
            """Check if this is an OpenLDAP 2.x attribute (PRIVATE)."""
            if isinstance(attr_definition, str):
                if not attr_definition or not attr_definition.strip():
                    return False

                if re.search(
                    FlextLdifServersOpenldap.Constants.SCHEMA_OPENLDAP_OLC_PATTERN,
                    attr_definition,
                    re.IGNORECASE,
                ):
                    return True

                return super().can_handle_attribute(attr_definition)
            if isinstance(attr_definition, m.Ldif.SchemaAttribute):
                if attr_definition.oid and re.search(
                    FlextLdifServersOpenldap.Constants.SCHEMA_OPENLDAP_OLC_PATTERN,
                    attr_definition.oid,
                    re.IGNORECASE,
                ):
                    return True

                return super().can_handle_attribute(attr_definition)
            return False

        def can_handle_objectclass(
            self,
            oc_definition: str | m.Ldif.SchemaObjectClass,
        ) -> bool:
            """Check if this is an OpenLDAP 2.x objectClass (PRIVATE)."""
            if isinstance(oc_definition, str):
                if re.search(
                    FlextLdifServersOpenldap.Constants.SCHEMA_OPENLDAP_OLC_PATTERN,
                    oc_definition,
                    re.IGNORECASE,
                ):
                    return True

                return super().can_handle_objectclass(oc_definition)
            if isinstance(oc_definition, m.Ldif.SchemaObjectClass):
                if oc_definition.oid and re.search(
                    FlextLdifServersOpenldap.Constants.SCHEMA_OPENLDAP_OLC_PATTERN,
                    oc_definition.oid,
                    re.IGNORECASE,
                ):
                    return True

                return super().can_handle_objectclass(oc_definition)
            return False

        def _transform_attribute_for_write(
            self,
            attr_data: m.Ldif.SchemaAttribute,
        ) -> m.Ldif.SchemaAttribute:
            """Transform attribute before writing (hook from base.py)."""
            return super()._transform_attribute_for_write(attr_data)

        def _transform_objectclass_for_write(
            self,
            oc_data: m.Ldif.SchemaObjectClass,
        ) -> m.Ldif.SchemaObjectClass:
            """Transform objectClass before writing (hook from base.py)."""
            return super()._transform_objectclass_for_write(oc_data)

    class Acl(FlextLdifServersRfc.Acl):
        """OpenLDAP 2.x ACL quirk (nested)."""

        def can_handle(self, acl_line: str | m.Ldif.Acl) -> bool:
            """Check if this is an OpenLDAP 2.x ACL."""
            if isinstance(acl_line, str):
                return self.can_handle_acl(acl_line)

            if hasattr(acl_line, "raw_acl"):
                raw_acl_value = getattr(acl_line, "raw_acl", None)
                if not raw_acl_value:
                    return False
                return self.can_handle_acl(str(raw_acl_value))
            return False

        def can_handle_acl(self, acl_line: str | m.Ldif.Acl) -> bool:
            """Check if this is an OpenLDAP 2.x ACL (internal)."""
            if isinstance(acl_line, m.Ldif.Acl):
                if not acl_line.raw_acl:
                    return False
                acl_line = acl_line.raw_acl
            if not isinstance(acl_line, str) or not acl_line:
                return False

            acl_content = acl_line
            olc_prefix = FlextLdifServersOpenldap.Constants.ACL_OLCACCESS_PREFIX
            if acl_line.startswith(olc_prefix):
                acl_content = acl_line[len(olc_prefix) :].strip()

            return bool(
                re.match(
                    FlextLdifServersOpenldap.Constants.ACL_INDEX_PREFIX_PATTERN,
                    acl_content,
                    re.IGNORECASE,
                ),
            ) or acl_content.startswith(
                FlextLdifServersOpenldap.Constants.ACL_START_PREFIX
                + f"{FlextLdifServersOpenldap.Constants.ACL_ATTRIBUTE_NAME}:",
            )

        def _write_acl(
            self,
            acl_data: FlextLdifModelsDomains.Acl,
        ) -> FlextResult[str]:
            """Write ACL data to RFC-compliant string format (internal)."""
            try:
                if acl_data.raw_acl:
                    return FlextResult[str].ok(acl_data.raw_acl)

                constants = FlextLdifServersOpenldap.Constants
                what = (
                    acl_data.target.target_dn
                    if acl_data.target
                    else constants.ACL_WILDCARD_TARGET
                )
                who = (
                    acl_data.subject.subject_value
                    if acl_data.subject
                    else constants.ACL_WILDCARD_TARGET
                )

                acl_parts = [
                    f"{constants.ACL_PREFIX_TO}{what}",
                ]
                acl_parts.append(f"{constants.ACL_PREFIX_BY}{who}")

                if acl_data.permissions:
                    perms = []
                    if acl_data.permissions.read:
                        perms.append("read")
                    if acl_data.permissions.write:
                        perms.append("write")
                    if perms:
                        acl_parts.append(",".join(perms))

                acl_str = " ".join(acl_parts)
                return FlextResult[str].ok(acl_str)

            except Exception as e:
                return FlextResult[str].fail(f"OpenLDAP 2.x ACL write failed: {e}")

        def _strip_acl_prefix_and_index(self, acl_line: str) -> str:
            """Remove olcAccess: prefix and {n} index from ACL line."""
            acl_content = acl_line
            if acl_line.startswith(
                f"{FlextLdifServersOpenldap.Constants.ACL_ATTRIBUTE_NAME}:",
            ):
                acl_content = acl_line[
                    len(
                        FlextLdifServersOpenldap.Constants.ACL_ATTRIBUTE_NAME + ":",
                    ) :
                ].strip()

            index_match = re.match(
                FlextLdifServersOpenldap.Constants.ACL_INDEX_PATTERN,
                acl_content,
            )
            if index_match:
                acl_content = index_match.group(2)

            return acl_content

        def _parse_what_clause(self, acl_content: str) -> tuple[str | None, list[str]]:
            """Parse "to <what>" clause and extract attributes."""
            to_match = re.match(
                FlextLdifServersOpenldap.Constants.ACL_TO_BY_PATTERN,
                acl_content,
                re.IGNORECASE,
            )
            if not to_match:
                return None, []

            what = to_match.group(1).strip()

            attributes: list[str] = []
            attrs_match = re.search(
                FlextLdifServersOpenldap.Constants.ACL_ATTRS_PATTERN,
                what,
                re.IGNORECASE,
            )
            if attrs_match:
                attr_string = attrs_match.group(1)
                attributes = [
                    attr.strip()
                    for attr in attr_string.split(
                        FlextLdifServersOpenldap.Constants.ACL_ATTRS_SEPARATOR,
                    )
                ]

            return what, attributes

        def _parse_by_clauses(self, acl_content: str) -> tuple[str, str]:
            """Parse "by <who> <access>" clauses."""
            by_matches = list(
                re.finditer(
                    FlextLdifServersOpenldap.Constants.ACL_BY_PATTERN,
                    acl_content,
                    re.IGNORECASE,
                ),
            )

            subject_value = (
                by_matches[0].group(1)
                if by_matches
                else FlextLdifServersOpenldap.Constants.ACL_SUBJECT_ANONYMOUS
            )

            access = (
                by_matches[0].group(2)
                if by_matches
                else FlextLdifServersOpenldap.Constants.ACL_DEFAULT_ACCESS
            )

            return subject_value, access

        def _build_openldap_acl_model(
            self,
            what: str,
            attributes: list[str],
            subject_value: str,
            access: str,
            acl_line: str,
        ) -> m.Ldif.Acl:
            """Build OpenLDAP Acl model from parsed components."""
            return m.Ldif.Acl(
                name=FlextLdifServersOpenldap.Constants.ACL_DEFAULT_NAME,
                target=m.Ldif.AclTarget(
                    target_dn=what,
                    attributes=attributes,
                ),
                subject=m.Ldif.AclSubject(
                    subject_type="all",
                    subject_value=subject_value,
                ),
                permissions=m.Ldif.AclPermissions(
                    read="read" in access,
                    write="write" in access,
                    add="write" in access,
                    delete="write" in access,
                    search="read" in access,
                    compare="read" in access,
                ),
                metadata=m.Ldif.QuirkMetadata.create_for(
                    self._get_server_type(),
                    extensions=m.Ldif.DynamicMetadata.from_dict({
                        "original_format": acl_line
                    }),
                ),
                raw_acl=acl_line,
            )

        def _parse_acl(self, acl_line: str) -> FlextResult[m.Ldif.Acl]:
            """Parse OpenLDAP 2.x ACL definition (internal)."""
            try:
                acl_content = self._strip_acl_prefix_and_index(acl_line)

                what, attributes = self._parse_what_clause(acl_content)

                if what is None:
                    acl_minimal = m.Ldif.Acl(
                        name=FlextLdifServersOpenldap.Constants.ACL_DEFAULT_NAME,
                        target=m.Ldif.AclTarget(
                            target_dn=FlextLdifServersOpenldap.Constants.ACL_WILDCARD_TARGET,
                            attributes=[],
                        ),
                        subject=m.Ldif.AclSubject(
                            subject_type=FlextLdifServersOpenldap.Constants.ACL_SUBJECT_TYPE_WHO,
                            subject_value=FlextLdifServersOpenldap.Constants.ACL_WILDCARD_TARGET,
                        ),
                        permissions=m.Ldif.AclPermissions(),
                        raw_acl=acl_line,
                        metadata=self.create_metadata(acl_line),
                    )

                    return FlextResult[m.Ldif.Acl].ok(acl_minimal)

                subject_value, access = self._parse_by_clauses(acl_content)

                acl = self._build_openldap_acl_model(
                    what,
                    attributes,
                    subject_value,
                    access,
                    acl_line,
                )

                return FlextResult[m.Ldif.Acl].ok(acl)

            except Exception as e:
                return FlextResult[m.Ldif.Acl].fail(
                    f"OpenLDAP 2.x ACL parsing failed: {e}",
                )

    class Entry(FlextLdifServersRfc.Entry):
        """OpenLDAP 2.x entry quirk (nested)."""

        def can_handle(
            self,
            entry_dn: str,
            attributes: dict[str, list[str]],
        ) -> bool:
            """Check if this quirk should handle the entry (PRIVATE)."""
            if not entry_dn:
                return False

            is_config_dn = any(
                marker in entry_dn.lower()
                for marker in FlextLdifServersOpenldap.Constants.DETECTION_DN_MARKERS
            )

            has_olc_attrs = any(attr.startswith("olc") for attr in attributes)

            object_classes_raw = attributes.get(
                c.Ldif.DictKeys.OBJECTCLASS,
                [],
            )

            object_classes_list: list[str] = []
            if isinstance(object_classes_raw, (list, tuple)):
                for item in (
                    object_classes_raw
                    if isinstance(object_classes_raw, list)
                    else [object_classes_raw]
                ):
                    if isinstance(item, str):
                        object_classes_list.append(item)
                    elif item is not None:
                        object_classes_list.append(str(item))
            elif isinstance(object_classes_raw, str):
                object_classes_list = [object_classes_raw]
            elif object_classes_raw is not None:
                object_classes_list = [str(object_classes_raw)]

            has_olc_classes = any(
                oc in FlextLdifServersOpenldap.Constants.OPENLDAP_2_OBJECTCLASSES
                for oc in object_classes_list
            )

            return is_config_dn or has_olc_attrs or has_olc_classes

        def _inject_validation_rules(
            self,
            entry: m.Ldif.Entry,
        ) -> m.Ldif.Entry:
            """Inject OpenLDAP-specific validation rules into Entry metadata via DI."""
            server_type = c.Ldif.ServerTypes.OPENLDAP.value

            validation_rules: dict[
                str,
                str
                | int
                | float
                | bool
                | dict[str, str | int | float | bool | list[str] | None]
                | list[str]
                | None,
            ] = {
                "requires_objectclass": (
                    server_type
                    in c.Ldif.ServerValidationRules.OBJECTCLASS_REQUIRED_SERVERS
                ),
                "requires_naming_attr": (
                    server_type
                    in c.Ldif.ServerValidationRules.NAMING_ATTR_REQUIRED_SERVERS
                ),
                "requires_binary_option": (
                    server_type
                    in c.Ldif.ServerValidationRules.BINARY_OPTION_REQUIRED_SERVERS
                ),
                "encoding_rules": {
                    "default_encoding": "utf-8",
                    "allowed_encodings": [
                        "utf-8",
                        "latin-1",
                        "iso-8859-1",
                        "ascii",
                    ],
                },
                "dn_case_rules": {
                    "preserve_case": True,
                    "normalize_to": None,
                },
                "acl_format_rules": {
                    "format": "olcAccess",
                    "attribute_name": "olcAccess",
                    "requires_target": True,
                    "requires_subject": True,
                },
                "track_deletions": True,
                "track_modifications": True,
                "track_conversions": True,
            }

            if entry.metadata is None:
                entry = entry.model_copy(
                    update={
                        "metadata": m.Ldif.QuirkMetadata.create_for(
                            "openldap",
                            extensions=m.Ldif.DynamicMetadata(),
                        ),
                    },
                )

            if entry.metadata is None:
                return entry

            entry.metadata.extensions["validation_rules"] = json.dumps(validation_rules)

            logger.debug(
                "Injected OpenLDAP validation rules into Entry metadata",
                entry_dn=entry.dn.value if entry.dn else None,
                requires_objectclass=validation_rules["requires_objectclass"],
                server_type=c.Ldif.ServerTypes.OPENLDAP.value,
                requires_naming_attr=validation_rules["requires_naming_attr"],
                requires_binary_option=validation_rules["requires_binary_option"],
                acl_format=validation_rules["acl_format_rules"],
            )

            return entry


__all__ = ["FlextLdifServersOpenldap"]
