"""Relaxed Quirks for Lenient LDIF Processing."""

from __future__ import annotations

import re
from typing import ClassVar

from flext_core import r
from flext_core.loggings import FlextLogger

from flext_ldif._models.domain import FlextLdifModelsDomains
from flext_ldif.constants import c
from flext_ldif.models import m
from flext_ldif.servers.rfc import FlextLdifServersRfc
from flext_ldif.typings import t
from flext_ldif.utilities import u

logger = FlextLogger.get_logger(__name__)


class FlextLdifServersRelaxed(FlextLdifServersRfc):
    """Relaxed mode server quirks for non-compliant LDIF."""

    class Constants(FlextLdifServersRfc.Constants):
        """Standardized constants for Relaxed (lenient) quirk."""

        SERVER_TYPE: ClassVar[str] = "relaxed"
        PRIORITY: ClassVar[int] = 200

        CANONICAL_NAME: ClassVar[str] = "relaxed"
        ALIASES: ClassVar[frozenset[str]] = frozenset(["relaxed", "lenient"])
        CAN_NORMALIZE_FROM: ClassVar[frozenset[str]] = frozenset(["relaxed"])
        CAN_DENORMALIZE_TO: ClassVar[frozenset[str]] = frozenset(["relaxed", "rfc"])

        ACL_FORMAT: ClassVar[str] = "rfc_generic"
        ACL_ATTRIBUTE_NAME: ClassVar[str] = "aci"

        OID_PATTERN: ClassVar[re.Pattern[str]] = re.compile(r"\(?\s*([0-9a-zA-Z._\-]+)")

        OID_NUMERIC_WITH_PAREN: ClassVar[str] = r"\(\s*([0-9]+(?:\.[0-9]+)+)"
        OID_NUMERIC_ANYWHERE: ClassVar[str] = r"([0-9]+\.[0-9]+(?:\.[0-9]+)*)"
        OID_ALPHANUMERIC_RELAXED: ClassVar[str] = r"\(\s*([a-zA-Z0-9._-]+)"

        SCHEMA_MUST_SEPARATOR: ClassVar[str] = "$"
        SCHEMA_MAY_SEPARATOR: ClassVar[str] = "$"
        SCHEMA_NAME_PATTERN: ClassVar[str] = r"NAME\s+['\"]?([^'\" ]+)['\"]?"

        ACL_DEFAULT_NAME: ClassVar[str] = "relaxed_acl"
        ACL_DEFAULT_TARGET_DN: ClassVar[str] = "*"
        ACL_DEFAULT_SUBJECT_TYPE: ClassVar[str] = "all"
        ACL_DEFAULT_SUBJECT_VALUE: ClassVar[str] = "*"
        ACL_WRITE_PREFIX: ClassVar[str] = "acl: "

        LDIF_DN_PREFIX: ClassVar[str] = "dn: "
        LDIF_ATTR_SEPARATOR: ClassVar[str] = ": "
        ENCODING_UTF8: ClassVar[str] = "utf-8"
        ENCODING_ERROR_HANDLING: ClassVar[str] = "replace"

        LDIF_NEWLINE: ClassVar[str] = "\n"
        LDIF_JOIN_SEPARATOR: ClassVar[str] = "\n"

    class Schema(FlextLdifServersRfc.Schema):
        """Relaxed schema quirk - main class for lenient LDIF processing."""

        def can_handle_attribute(
            self,
            attr_definition: str | m.Ldif.SchemaAttribute,
        ) -> bool:
            """Accept any attribute definition in relaxed mode."""
            if isinstance(attr_definition, str):
                return bool(attr_definition.strip())
            return True

        def _extract_oid_from_attribute(self, attr_definition: str) -> str | None:
            """Extract OID from attribute definition using multiple strategies."""
            oid = u.Ldif.LdifParser.extract_oid(attr_definition)
            if oid:
                return oid

            oid_match = re.search(
                FlextLdifServersRelaxed.Constants.OID_NUMERIC_WITH_PAREN,
                attr_definition,
            )
            if oid_match:
                return oid_match.group(1)

            oid_match = re.search(
                FlextLdifServersRelaxed.Constants.OID_NUMERIC_ANYWHERE,
                attr_definition,
            )
            if oid_match:
                return oid_match.group(1)

            oid_match = re.search(
                FlextLdifServersRelaxed.Constants.OID_ALPHANUMERIC_RELAXED,
                attr_definition,
            )
            if oid_match:
                return oid_match.group(1)

            return None

        def _parse_attribute(
            self,
            attr_definition: str,
        ) -> r[m.Ldif.SchemaAttribute]:
            """Parse attribute with best-effort approach using RFC baseline."""
            if not attr_definition or not attr_definition.strip():
                return r[m.Ldif.SchemaAttribute].fail(
                    "Attribute definition cannot be empty",
                )

            parent_result = super()._parse_attribute(attr_definition)
            if parent_result.is_success:
                attribute = parent_result.value

                if not attribute.metadata:
                    attribute.metadata = m.Ldif.QuirkMetadata(
                        quirk_type=self._get_server_type(),
                        extensions=m.Ldif.DynamicMetadata(
                            original_format=attr_definition.strip(),
                            schema_source_server="relaxed",
                        ),
                    )
                else:
                    if not attribute.metadata.extensions:
                        attribute.metadata.extensions = m.Ldif.DynamicMetadata()
                    attribute.metadata.quirk_type = self._get_server_type()

                    if not attribute.metadata.extensions.get("original_format"):
                        attribute.metadata.extensions["original_format"] = (
                            attr_definition.strip()
                        )
                    attribute.metadata.extensions["schema_source_server"] = "relaxed"
                return r[m.Ldif.SchemaAttribute].ok(attribute)

            logger.debug(
                "RFC parser failed, using best-effort parsing",
                error=str(parent_result.error),
            )
            try:
                oid = self._extract_oid_from_attribute(attr_definition)
                if not oid:
                    return r[m.Ldif.SchemaAttribute].fail(
                        "Cannot extract OID from attribute definition",
                    )

                name_match = re.search(
                    FlextLdifServersRelaxed.Constants.SCHEMA_NAME_PATTERN,
                    attr_definition,
                    re.IGNORECASE,
                )
                name = name_match.group(1) if name_match else oid

                metadata = m.Ldif.QuirkMetadata(
                    quirk_type=self._get_server_type(),
                    extensions=m.Ldif.DynamicMetadata(
                        original_format=attr_definition.strip(),
                        schema_source_server="relaxed",
                    ),
                )

                attr_domain = m.Ldif.SchemaAttribute(
                    name=name,
                    oid=oid,
                    desc=None,
                    sup=None,
                    equality=None,
                    ordering=None,
                    substr=None,
                    syntax=None,
                    length=None,
                    usage=None,
                    single_value=False,
                    no_user_modification=False,
                    metadata=metadata,
                    x_origin=None,
                    x_file_ref=None,
                    x_name=None,
                    x_alias=None,
                    x_oid=None,
                )
                return r[m.Ldif.SchemaAttribute].ok(
                    attr_domain,
                )
            except Exception as e:
                logger.debug(
                    "Relaxed attribute parse exception",
                    error=str(e),
                    error_type=type(e).__name__,
                )

                return r[m.Ldif.SchemaAttribute].fail(
                    f"Failed to parse attribute definition: {e}",
                )

        def can_handle_objectclass(
            self,
            oc_definition: str | m.Ldif.SchemaObjectClass,
        ) -> bool:
            """Accept any objectClass definition in relaxed mode."""
            if isinstance(oc_definition, str):
                return bool(oc_definition.strip())
            return True

        def _enhance_objectclass_metadata(
            self,
            objectclass: m.Ldif.SchemaObjectClass,
            original_definition: str,
        ) -> m.Ldif.SchemaObjectClass:
            """Enhance objectClass metadata to indicate relaxed mode parsing."""
            if not objectclass.metadata:
                objectclass.metadata = m.Ldif.QuirkMetadata(
                    quirk_type=self._get_server_type(),
                    extensions=m.Ldif.DynamicMetadata(
                        original_format=original_definition.strip(),
                        schema_source_server="relaxed",
                    ),
                )
            else:
                if not objectclass.metadata.extensions:
                    objectclass.metadata.extensions = m.Ldif.DynamicMetadata()
                objectclass.metadata.quirk_type = self._get_server_type()

                if not objectclass.metadata.extensions.get("original_format"):
                    objectclass.metadata.extensions["original_format"] = (
                        original_definition.strip()
                    )
                objectclass.metadata.extensions["schema_source_server"] = "relaxed"
            return objectclass

        def _extract_oid_with_fallback_patterns(
            self,
            definition: str,
        ) -> str | None:
            """Extract OID using multiple fallback patterns for relaxed mode."""
            oid = u.Ldif.LdifParser.extract_oid(definition)
            if oid:
                return oid

            oid_match = re.search(
                FlextLdifServersRelaxed.Constants.OID_NUMERIC_WITH_PAREN,
                definition,
            )
            if oid_match:
                return oid_match.group(1)

            oid_match = re.search(
                FlextLdifServersRelaxed.Constants.OID_NUMERIC_ANYWHERE,
                definition,
            )
            if oid_match:
                return oid_match.group(1)

            oid_match = re.search(
                FlextLdifServersRelaxed.Constants.OID_ALPHANUMERIC_RELAXED,
                definition,
            )
            if oid_match:
                return oid_match.group(1)

            return None

        def _extract_sup_from_objectclass(
            self,
            oc_definition: str,
        ) -> str | None:
            """Extract SUP (superior) field from objectClass definition."""
            sup_match = re.search(
                r"\bSUP\s+(?:\(\s*([^)]+)\s*\)|(\w+))\b",
                oc_definition,
            )
            if not sup_match:
                return None

            if sup_match.group(1):
                sup_value = sup_match.group(1).strip()
            elif sup_match.group(2):
                sup_value = sup_match.group(2).strip()
            else:
                sup_value = ""

            if FlextLdifServersRelaxed.Constants.SCHEMA_MUST_SEPARATOR in sup_value:
                return next(
                    s.strip()
                    for s in sup_value.split(
                        FlextLdifServersRelaxed.Constants.SCHEMA_MUST_SEPARATOR,
                    )
                )
            return sup_value

        def _extract_must_may_from_objectclass(
            self,
            oc_definition: str,
        ) -> tuple[list[str] | None, list[str] | None]:
            """Extract MUST and MAY fields from objectClass definition."""
            must = None
            must_match = re.search(
                r"\bMUST\s+(?:\(\s*([^)]+)\s*\)|(\w+))\b",
                oc_definition,
            )
            if must_match:
                if must_match.group(1):
                    must_value = must_match.group(1).strip()
                elif must_match.group(2):
                    must_value = must_match.group(2).strip()
                else:
                    must_value = ""
                must = [
                    m.strip()
                    for m in must_value.split(
                        FlextLdifServersRelaxed.Constants.SCHEMA_MUST_SEPARATOR,
                    )
                ]

            may = None
            may_match = re.search(
                r"\bMAY\s+(?:\(\s*([^)]+)\s*\)|(\w+))\b",
                oc_definition,
            )
            if may_match:
                if may_match.group(1):
                    may_value = may_match.group(1).strip()
                elif may_match.group(2):
                    may_value = may_match.group(2).strip()
                else:
                    may_value = ""
                may = [
                    m.strip()
                    for m in may_value.split(
                        FlextLdifServersRelaxed.Constants.SCHEMA_MAY_SEPARATOR,
                    )
                ]

            return (must, may)

        def _parse_objectclass_relaxed(
            self,
            oc_definition: str,
        ) -> r[m.Ldif.SchemaObjectClass]:
            """Parse objectClass with relaxed/best-effort parsing using utilities."""
            oid = self._extract_oid_with_fallback_patterns(oc_definition)
            if not oid:
                return r[m.Ldif.SchemaObjectClass].fail(
                    "Failed to extract OID from objectClass definition",
                )

            name = u.Ldif.LdifParser.extract_optional_field(
                oc_definition,
                r"\bNAME\s+(?:'([^']+)'|\(([^)]+)\))\b",
                default=oid,
            )
            desc = u.Ldif.LdifParser.extract_optional_field(
                oc_definition,
                r"\bDESC\s+'([^']+)'\b",
            )

            sup = self._extract_sup_from_objectclass(oc_definition)

            kind_match = re.search(
                r"\b(ABSTRACT|STRUCTURAL|AUXILIARY)\b",
                oc_definition,
                re.IGNORECASE,
            )
            kind = (
                kind_match.group(1).upper()
                if kind_match
                else c.Ldif.SchemaKind.STRUCTURAL.value
            )

            must, may = self._extract_must_may_from_objectclass(oc_definition)

            metadata = m.Ldif.QuirkMetadata(
                quirk_type=self._get_server_type(),
                extensions=m.Ldif.DynamicMetadata(
                    original_format=oc_definition.strip(),
                    schema_source_server="relaxed",
                ),
            )

            objectclass_name = name or oid
            return r[m.Ldif.SchemaObjectClass].ok(
                m.Ldif.SchemaObjectClass(
                    name=objectclass_name,
                    oid=oid,
                    desc=desc,
                    sup=sup,
                    kind=kind,
                    must=must,
                    may=may,
                    metadata=metadata,
                ),
            )

        def _parse_objectclass(
            self,
            oc_definition: str,
        ) -> r[m.Ldif.SchemaObjectClass]:
            """Parse objectClass with best-effort approach using RFC baseline."""
            if not oc_definition or not oc_definition.strip():
                return r[m.Ldif.SchemaObjectClass].fail(
                    "ObjectClass definition cannot be empty",
                )

            parent_result = super()._parse_objectclass(oc_definition)
            if parent_result.is_success:
                objectclass = parent_result.value
                return r[m.Ldif.SchemaObjectClass].ok(
                    self._enhance_objectclass_metadata(objectclass, oc_definition),
                )

            logger.debug(
                "RFC parser failed, using best-effort parsing",
                error=str(parent_result.error),
            )
            return self._parse_objectclass_relaxed(oc_definition)

        def _write_attribute(
            self,
            attr_data: m.Ldif.SchemaAttribute,
        ) -> r[str]:
            """Write attribute to RFC format - stringify in relaxed mode."""
            parent_result = super()._write_attribute(attr_data)
            if parent_result.is_success:
                return parent_result

            source_server = None
            if attr_data.metadata and attr_data.metadata.extensions:
                source_server = attr_data.metadata.extensions.get(
                    c.Ldif.MetadataKeys.SCHEMA_SOURCE_SERVER,
                )

            if (
                source_server == "relaxed"
                and attr_data.metadata
                and attr_data.metadata.extensions.get("original_format")
            ):
                original_format_raw = attr_data.metadata.extensions.get(
                    "original_format",
                    "",
                )
                if not isinstance(original_format_raw, str):
                    msg = f"Expected str, got {type(original_format_raw)}"
                    raise TypeError(msg)
                return r[str].ok(original_format_raw)

            if not attr_data.oid:
                return r[str].fail("Attribute OID is required for writing")

            attr_name: str
            attr_name = attr_data.name or attr_data.oid
            return r[str].ok(f"( {attr_data.oid} NAME '{attr_name}' )")

        def _write_objectclass(
            self,
            oc_data: m.Ldif.SchemaObjectClass,
        ) -> r[str]:
            """Write objectClass to RFC format - stringify in relaxed mode."""
            parent_result = super()._write_objectclass(oc_data)
            if parent_result.is_success:
                return parent_result

            source_server = None
            if oc_data.metadata and oc_data.metadata.extensions:
                source_server = oc_data.metadata.extensions.get(
                    c.Ldif.MetadataKeys.SCHEMA_SOURCE_SERVER,
                )

            if (
                source_server == "relaxed"
                and oc_data.metadata
                and oc_data.metadata.extensions.get("original_format")
            ):
                original_format_raw = oc_data.metadata.extensions.get(
                    "original_format",
                    "",
                )
                if not isinstance(original_format_raw, str):
                    msg = f"Expected str, got {type(original_format_raw)}"
                    raise TypeError(msg)
                return r[str].ok(original_format_raw)

            if not oc_data.oid:
                return r[str].fail("ObjectClass OID is required for writing")

            oc_name: str
            oc_name = oc_data.name or oc_data.oid

            oc_kind: str
            oc_kind = oc_data.kind or c.Ldif.SchemaKind.STRUCTURAL.value
            return r[str].ok(f"( {oc_data.oid} NAME '{oc_name}' {oc_kind} )")

    class Acl(FlextLdifServersRfc.Acl):
        """Relaxed ACL quirk for lenient LDIF processing."""

        def can_handle(self, acl_line: t.Ldif.AclOrString) -> bool:
            """Check if this is a relaxed ACL (public method)."""
            if isinstance(acl_line, str):
                return self.can_handle_acl(acl_line)
            return self.can_handle_acl(acl_line)

        def can_handle_acl(
            self,
            acl_line: str | m.Ldif.Acl | object,
        ) -> bool:
            """Accept any ACL line in relaxed mode."""
            _ = acl_line
            return True

        def _parse_acl(self, acl_line: str) -> r[m.Ldif.Acl]:
            """Parse ACL with best-effort approach."""
            if not acl_line or not acl_line.strip():
                return r[m.Ldif.Acl].fail(
                    "ACL line cannot be empty",
                )
            try:
                parent_result = super()._parse_acl(acl_line)
                if parent_result.is_success:
                    acl = parent_result.value

                    if not acl.metadata:
                        updated_acl = acl.model_copy(
                            update={
                                "metadata": m.Ldif.QuirkMetadata(
                                    quirk_type=self._get_server_type(),
                                    extensions=m.Ldif.DynamicMetadata.model_validate({
                                        "original_format": acl_line.strip(),
                                    }),
                                ),
                            },
                        )
                    else:
                        updated_extensions = (
                            acl.metadata.extensions or m.Ldif.DynamicMetadata()
                        )
                        updated_metadata = acl.metadata.model_copy(
                            update={
                                "quirk_type": self._get_server_type(),
                                "extensions": updated_extensions,
                            },
                        )
                        updated_acl = acl.model_copy(
                            update={"metadata": updated_metadata},
                        )
                    return r[m.Ldif.Acl].ok(updated_acl)

                relaxed_acl = m.Ldif.Acl(
                    name=FlextLdifServersRelaxed.Constants.ACL_DEFAULT_NAME,
                    target=m.Ldif.AclTarget(
                        target_dn=FlextLdifServersRelaxed.Constants.ACL_DEFAULT_TARGET_DN,
                        attributes=[],
                    ),
                    subject=m.Ldif.AclSubject(
                        subject_type="all",
                        subject_value=FlextLdifServersRelaxed.Constants.ACL_DEFAULT_SUBJECT_VALUE,
                    ),
                    permissions=m.Ldif.AclPermissions(),
                    raw_acl=acl_line,
                    metadata=m.Ldif.QuirkMetadata(
                        quirk_type=self._get_server_type(),
                        extensions=m.Ldif.DynamicMetadata.model_validate({
                            "original_format": acl_line.strip(),
                        }),
                    ),
                )
                return r[m.Ldif.Acl].ok(relaxed_acl)
            except Exception as e:
                logger.debug(
                    "Relaxed ACL parse failed",
                    error=str(e),
                )
                return r[m.Ldif.Acl].fail(
                    f"Failed to parse ACL: {e}",
                )

        def _write_acl(self, acl_data: FlextLdifModelsDomains.Acl) -> r[str]:
            """Write ACL to RFC format - stringify in relaxed mode."""
            parent_result = super()._write_acl(acl_data)
            if parent_result.is_success:
                return parent_result

            if acl_data.raw_acl and isinstance(acl_data.raw_acl, str):
                return r[str].ok(acl_data.raw_acl)

            acl_name = (
                acl_data.name or FlextLdifServersRelaxed.Constants.ACL_DEFAULT_NAME
            )
            return r[str].ok(
                f"{FlextLdifServersRelaxed.Constants.ACL_WRITE_PREFIX}{acl_name}",
            )

        def can_handle_attribute(
            self,
            attribute: m.Ldif.SchemaAttribute,
        ) -> bool:
            """Check if this ACL quirk should be aware of a specific attribute definition."""
            _ = attribute
            return True

        def can_handle_objectclass(
            self,
            objectclass: m.Ldif.SchemaObjectClass,
        ) -> bool:
            """Check if this ACL quirk should be aware of a specific objectClass definition."""
            _ = objectclass
            return True

    class Entry(FlextLdifServersRfc.Entry):
        """Relaxed entry quirk for lenient LDIF processing."""

        def process_entry(
            self,
            entry: m.Ldif.Entry,
        ) -> r[m.Ldif.Entry]:
            """Process entry for relaxed mode."""
            return r[m.Ldif.Entry].ok(entry)

        def can_handle(
            self,
            entry_dn: str,
            attributes: dict[str, list[str]],
        ) -> bool:
            """Accept any entry in relaxed mode."""
            _ = entry_dn
            _ = attributes
            return True

        def _parse_entry(
            self,
            entry_dn: str,
            entry_attrs: dict[str, list[str | bytes]],
        ) -> r[m.Ldif.Entry]:
            """Parse entry with best-effort approach."""
            try:
                if not entry_dn or not entry_dn.strip():
                    return r[m.Ldif.Entry].fail(
                        "Entry DN cannot be empty",
                    )

                effective_dn = m.Ldif.DN(value=entry_dn.strip())

                if isinstance(entry_attrs, m.Ldif.Attributes):
                    ldif_attrs = entry_attrs
                else:
                    attr_dict: dict[str, list[str]] = {}

                    attr_key: str
                    attr_value: list[str | bytes]
                    for attr_key, attr_value in entry_attrs.items():
                        converted_list: list[str] = []
                        for v in attr_value:
                            if isinstance(v, bytes):
                                converted_list.append(
                                    v.decode(
                                        FlextLdifServersRelaxed.Constants.ENCODING_UTF8,
                                        errors=FlextLdifServersRelaxed.Constants.ENCODING_ERROR_HANDLING,
                                    ),
                                )
                            else:
                                converted_list.append(str(v))
                        attr_dict[str(attr_key)] = converted_list
                    ldif_attrs = m.Ldif.Attributes(attributes=attr_dict)

                original_attribute_case: dict[str, str] = {}
                for attr_name in entry_attrs:
                    attr_str = str(attr_name)

                    if attr_str.lower() == "objectclass":
                        original_attribute_case["objectClass"] = attr_str

                format_details = m.Ldif.FormatDetails(
                    dn_line=entry_dn,
                    spacing=entry_dn,
                )

                case_metadata = m.Ldif.DynamicMetadata.model_validate(
                    original_attribute_case,
                )
                metadata = m.Ldif.QuirkMetadata(
                    quirk_type="relaxed",
                    original_format_details=format_details,
                    original_attribute_case=case_metadata,
                    extensions=m.Ldif.DynamicMetadata(
                        server_type="relaxed",
                        relaxed_mode=True,
                    ),
                )

                entry = m.Ldif.Entry(
                    dn=effective_dn,
                    attributes=ldif_attrs,
                    metadata=metadata,
                )
                return r[m.Ldif.Entry].ok(entry)
            except Exception as e:
                logger.debug(
                    "Relaxed entry creation failed",
                    error=str(e),
                    error_type=type(e).__name__,
                )
                return r[m.Ldif.Entry].fail(
                    f"Failed to parse entry: {e}",
                )

        def _parse_content(
            self,
            ldif_content: str,
        ) -> r[list[m.Ldif.Entry]]:
            """Parse raw LDIF content string into Entry models (internal)."""
            parent_result = super()._parse_content(ldif_content)
            if parent_result.is_success:
                return parent_result

            logger.debug(
                "RFC parser failed, using relaxed mode",
                error=str(parent_result.error) if parent_result.error else None,
                error_type=type(parent_result.error).__name__
                if parent_result.error
                else None,
            )

            return u.Ldif.Parsers.Content.parse(
                ldif_content=ldif_content,
                server_type=self._get_server_type(),
                parse_entry_hook=self._adapted_parse_entry_relaxed,
            )

        def _adapted_parse_entry_relaxed(
            self,
            entry_content: str,
        ) -> r[m.Ldif.Entry]:
            """Parse entry content in relaxed mode (extracted from _parse_content)."""
            dn: str = ""
            attrs: dict[str, list[str | bytes]] = {}
            for raw_line in entry_content.split("\n"):
                line = raw_line.strip()
                if not line or line.startswith("#"):
                    continue

                if line.startswith(" ") and attrs:
                    last_key = list(attrs.keys())[-1]
                    if attrs[last_key]:
                        attrs[last_key][-1] = str(attrs[last_key][-1]) + line[1:]
                    continue
                if ":" not in line:
                    continue
                key, _, value = line.partition(":")
                key = key.strip()
                value = value.strip()
                if key.lower() == "dn":
                    dn = value
                else:
                    if key not in attrs:
                        attrs[key] = []
                    attrs[key].append(value)
            if not dn:
                return r[m.Ldif.Entry].fail(
                    "No DN found in entry",
                )
            return self._parse_entry(dn, attrs)

        def _write_entry(
            self,
            entry_data: m.Ldif.Entry,
        ) -> r[str]:
            """Write Entry model to RFC-compliant LDIF string format (internal)."""
            parent_result = super()._write_entry(entry_data)
            if parent_result.is_success:
                return parent_result

            logger.debug(
                "RFC write failed, using relaxed mode",
                error=str(parent_result.error) if parent_result.error else None,
                error_type=type(parent_result.error).__name__
                if parent_result.error
                else None,
            )
            try:
                ldif_lines: list[str] = []

                if not entry_data.dn or not entry_data.dn.value:
                    return r[str].fail("Entry DN is required for LDIF output")
                ldif_lines.append(
                    f"{FlextLdifServersRelaxed.Constants.LDIF_DN_PREFIX}{entry_data.dn.value}",
                )

                if entry_data.attributes and entry_data.attributes.attributes:
                    for (
                        attr_name,
                        attr_values,
                    ) in entry_data.attributes.attributes.items():
                        ldif_lines.extend(
                            f"{attr_name}{FlextLdifServersRelaxed.Constants.LDIF_ATTR_SEPARATOR}{value}"
                            for value in attr_values
                        )

                ldif_text = FlextLdifServersRelaxed.Constants.LDIF_JOIN_SEPARATOR.join(
                    ldif_lines,
                )
                if ldif_text and not ldif_text.endswith(
                    FlextLdifServersRelaxed.Constants.LDIF_NEWLINE,
                ):
                    ldif_text += FlextLdifServersRelaxed.Constants.LDIF_NEWLINE

                return r[str].ok(ldif_text)

            except Exception as e:
                logger.debug(
                    "Write entry failed",
                    error=str(e),
                    error_type=type(e).__name__,
                )
                return r[str].fail(f"Failed to write entry: {e}")

        def can_handle_attribute(
            self,
            attribute: m.Ldif.SchemaAttribute,
        ) -> bool:
            """Check if this Entry quirk has special handling for an attribute definition."""
            _ = attribute
            return True

        def can_handle_objectclass(
            self,
            objectclass: m.Ldif.SchemaObjectClass,
        ) -> bool:
            """Check if this Entry quirk has special handling for an objectClass definition."""
            _ = objectclass
            return True

        def normalize_dn(self, dn: str) -> r[str]:
            """Normalize DN using RFC 4514 compliant utility."""
            if not dn or not dn.strip():
                return r[str].fail("DN cannot be empty")
            try:
                norm_result = u.Ldif.DN.norm(dn)
                if norm_result.is_success:
                    return r[str].ok(norm_result.value)

                return r[str].fail(
                    f"DN normalization failed for DN: {dn}: {norm_result.error}",
                )
            except Exception as e:
                logger.debug(
                    "DN normalization exception",
                    error=str(e),
                    error_type=type(e).__name__,
                )
                return r[str].fail(f"DN normalization failed: {e}")


__all__ = [
    "FlextLdifServersRelaxed",
]

__all__ = [
    "FlextLdifServersRelaxed",
]
