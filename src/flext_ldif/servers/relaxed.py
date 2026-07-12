"""Relaxed Servers for Lenient LDIF Processing."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, ClassVar, override

from flext_ldif import c, m, p, r, t, u
from flext_ldif.servers.rfc import FlextLdifServersRfc

if TYPE_CHECKING:
    from collections.abc import (
        MutableMapping,
    )


class FlextLdifServersRelaxed(FlextLdifServersRfc):
    """Relaxed mode server servers for non-compliant LDIF."""

    class Constants(FlextLdifServersRfc.Constants):
        """Standardized constants for Relaxed (lenient) server."""

        SERVER_TYPE: ClassVar[str] = "relaxed"
        PRIORITY: ClassVar[int] = 200
        CANONICAL_NAME: ClassVar[str] = "relaxed"
        ALIASES: ClassVar[frozenset[str]] = frozenset(["relaxed", "lenient"])
        CAN_NORMALIZE_FROM: ClassVar[frozenset[str]] = frozenset(["relaxed"])
        CAN_DENORMALIZE_TO: ClassVar[frozenset[str]] = frozenset(["relaxed", "rfc"])
        ACL_FORMAT: ClassVar[str] = "rfc_generic"
        ACL_ATTRIBUTE_NAME: ClassVar[str] = "aci"
        OID_PATTERN: ClassVar[t.Ldif.RegexPattern] = re.compile(
            r"\(\s*([0-9a-zA-Z._\-]+)",
        )
        OID_NUMERIC_WITH_PAREN: ClassVar[str] = "\\(\\s*([0-9]+(?:\\.[0-9]+)+)"
        OID_NUMERIC_WITH_PAREN_RE: ClassVar[t.Ldif.RegexPattern] = re.compile(
            OID_NUMERIC_WITH_PAREN,
        )
        OID_NUMERIC_ANYWHERE: ClassVar[str] = "([0-9]+\\.[0-9]+(?:\\.[0-9]+)*)"
        OID_NUMERIC_ANYWHERE_RE: ClassVar[t.Ldif.RegexPattern] = re.compile(
            OID_NUMERIC_ANYWHERE,
        )
        OID_ALPHANUMERIC_RELAXED: ClassVar[str] = "\\(\\s*([a-zA-Z0-9._-]+)"
        OID_ALPHANUMERIC_RELAXED_RE: ClassVar[t.Ldif.RegexPattern] = re.compile(
            OID_ALPHANUMERIC_RELAXED,
        )
        SCHEMA_MUST_SEPARATOR: ClassVar[str] = "$"
        SCHEMA_MAY_SEPARATOR: ClassVar[str] = "$"
        SCHEMA_NAME_PATTERN: ClassVar[str] = "NAME\\s+['\\\"]?([^'\\\" ]+)['\\\"]?"
        SCHEMA_NAME_RE: ClassVar[t.Ldif.RegexPattern] = re.compile(
            SCHEMA_NAME_PATTERN,
            re.IGNORECASE,
        )
        ACL_DEFAULT_NAME: ClassVar[str] = "relaxed_acl"
        ACL_DEFAULT_TARGET_DN: ClassVar[str] = "*"
        ACL_DEFAULT_SUBJECT_TYPE: ClassVar[str] = "all"
        ACL_DEFAULT_SUBJECT_VALUE: ClassVar[str] = "*"
        ACL_WRITE_PREFIX: ClassVar[str] = "acl: "
        LDIF_DN_PREFIX: ClassVar[str] = "dn: "
        LDIF_ATTR_SEPARATOR: ClassVar[str] = ": "
        ENCODING_ERROR_HANDLING: ClassVar[str] = "replace"
        LDIF_NEWLINE: ClassVar[str] = "\n"
        LDIF_JOIN_SEPARATOR: ClassVar[str] = "\n"

    class Schema(FlextLdifServersRfc.Schema):
        """Relaxed schema server - main class for lenient LDIF processing."""

        def _enhance_schema_item_metadata(
            self,
            schema_item: m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass,
            original_definition: str,
        ) -> m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass:
            if not schema_item.metadata:
                schema_item.metadata = m.Ldif.ServerMetadata.model_validate({
                    "server_type": self._get_server_type(),
                    "extensions": m.Ldif.DynamicMetadata.model_validate({
                        "original_format": original_definition.strip(),
                        "schema_source_server": "relaxed",
                    }),
                })
                return schema_item
            if not schema_item.metadata.extensions:
                schema_item.metadata.extensions = m.Ldif.DynamicMetadata()
            schema_item.metadata.server_type = self._get_server_type()
            if not schema_item.metadata.extensions.get("original_format"):
                schema_item.metadata.extensions["original_format"] = (
                    original_definition.strip()
                )
            schema_item.metadata.extensions["schema_source_server"] = "relaxed"
            return schema_item

        @override
        def can_handle_attribute(
            self,
            attr_definition: str | m.Ldif.SchemaAttribute,
        ) -> bool:
            """Accept any attribute definition in relaxed mode."""
            if not isinstance(attr_definition, str):
                return True
            return bool(attr_definition.strip())

        @override
        def can_handle_objectclass(
            self,
            oc_definition: str | m.Ldif.SchemaObjectClass,
        ) -> bool:
            """Accept any objectClass definition in relaxed mode."""
            if not isinstance(oc_definition, str):
                return True
            return bool(oc_definition.strip())

        def _enhance_objectclass_metadata(
            self,
            objectclass: m.Ldif.SchemaObjectClass,
            original_definition: str,
        ) -> m.Ldif.SchemaObjectClass:
            """Enhance objectClass metadata to indicate relaxed mode parsing."""
            result = self._enhance_schema_item_metadata(
                schema_item=objectclass,
                original_definition=original_definition,
            )
            # _enhance_schema_item_metadata preserves the concrete type at runtime
            if isinstance(result, m.Ldif.SchemaObjectClass):
                return result
            return objectclass

        def _extract_must_may_from_objectclass(
            self,
            oc_definition: str,
        ) -> tuple[t.MutableSequenceOf[str] | None, t.MutableSequenceOf[str] | None]:
            """Extract MUST and MAY fields from objectClass definition."""
            must = None
            must_match = c.Ldif.SCHEMA_OBJECTCLASS_MUST_RE.search(oc_definition)
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
            may_match = c.Ldif.SCHEMA_OBJECTCLASS_MAY_RE.search(oc_definition)
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

        def _extract_oid_with_fallback_patterns(self, definition: str) -> str | None:
            """Extract OID using multiple fallback patterns for relaxed mode."""
            oid_result = u.Ldif.extract_oid(definition)
            if oid_result.success:
                oid_val: str = oid_result.value
                return oid_val
            oid_match = (
                FlextLdifServersRelaxed.Constants.OID_NUMERIC_WITH_PAREN_RE.search(
                    definition,
                )
            )
            if oid_match:
                paren_oid: str = oid_match.group(1)
                return paren_oid
            oid_match = (
                FlextLdifServersRelaxed.Constants.OID_NUMERIC_ANYWHERE_RE.search(
                    definition,
                )
            )
            if oid_match:
                anywhere_oid: str = oid_match.group(1)
                return anywhere_oid
            oid_match = (
                FlextLdifServersRelaxed.Constants.OID_ALPHANUMERIC_RELAXED_RE.search(
                    definition,
                )
            )
            if oid_match:
                relaxed_oid: str = oid_match.group(1)
                return relaxed_oid
            return None

        def _extract_sup_from_objectclass(self, oc_definition: str) -> str | None:
            """Extract SUP (superior) field from objectClass definition."""
            sup_match = c.Ldif.SCHEMA_OBJECTCLASS_SUP_RE.search(oc_definition)
            if not sup_match:
                return None
            if sup_match.group(1):
                sup_value = sup_match.group(1).strip()
            elif sup_match.group(2):
                sup_value = sup_match.group(2).strip()
            else:
                sup_value = ""
            if FlextLdifServersRelaxed.Constants.SCHEMA_MUST_SEPARATOR in sup_value:
                first_part: str = next(
                    s.strip()
                    for s in sup_value.split(
                        FlextLdifServersRelaxed.Constants.SCHEMA_MUST_SEPARATOR,
                    )
                )
                return first_part
            sup_value_str: str = sup_value
            return sup_value_str

        @override
        def _parse_attribute(
            self,
            attr_definition: str,
        ) -> p.Result[m.Ldif.SchemaAttribute]:
            """Parse attribute with best-effort approach using RFC baseline."""
            if not attr_definition or not attr_definition.strip():
                return r[m.Ldif.SchemaAttribute].fail(
                    "Attribute definition cannot be empty",
                )
            parent_result = super()._parse_attribute(attr_definition)
            if parent_result.success:
                attribute = parent_result.value
                self._enhance_schema_item_metadata(
                    schema_item=attribute,
                    original_definition=attr_definition,
                )
                return r[m.Ldif.SchemaAttribute].ok(attribute)
            self.logger.debug(
                f"RFC parser failed, using best-effort parsing: {parent_result.error}",
            )
            try:
                return self._parse_relaxed_attribute(attr_definition)
            except c.Ldif.EXC_LDIF_PARSE as e:
                self.logger.debug(
                    "Relaxed attribute parse exception: %s",
                    e,
                )
                return r[m.Ldif.SchemaAttribute].fail(
                    f"Failed to parse attribute definition: {e}",
                )

        def _parse_relaxed_attribute(
            self,
            attr_definition: str,
        ) -> p.Result[m.Ldif.SchemaAttribute]:
            """Parse an attribute definition using relaxed fallback rules."""
            oid = self._extract_oid_with_fallback_patterns(attr_definition)
            if not oid:
                return r[m.Ldif.SchemaAttribute].fail(
                    "Cannot extract OID from attribute definition",
                )
            name_match = FlextLdifServersRelaxed.Constants.SCHEMA_NAME_RE.search(
                attr_definition,
            )
            name = name_match.group(1) if name_match else oid
            metadata = m.Ldif.ServerMetadata.model_validate({
                "server_type": self._get_server_type(),
                "extensions": m.Ldif.DynamicMetadata.model_validate({
                    "original_format": attr_definition.strip(),
                    "schema_source_server": "relaxed",
                }),
            })
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
                collective=False,
                no_user_modification=False,
                immutable=False,
                user_modification=True,
                obsolete=False,
                metadata=metadata,
                x_origin=None,
                x_file_ref=None,
                x_name=None,
                x_alias=None,
                x_oid=None,
            )
            return r[m.Ldif.SchemaAttribute].ok(attr_domain)

        @override
        def _parse_objectclass(
            self,
            oc_definition: str,
        ) -> p.Result[m.Ldif.SchemaObjectClass]:
            """Parse objectClass with best-effort approach using RFC baseline."""
            if not oc_definition or not oc_definition.strip():
                return r[m.Ldif.SchemaObjectClass].fail(
                    "ObjectClass definition cannot be empty",
                )
            parent_result = super()._parse_objectclass(oc_definition)
            if parent_result.success:
                objectclass = parent_result.value
                return r[m.Ldif.SchemaObjectClass].ok(
                    self._enhance_objectclass_metadata(objectclass, oc_definition),
                )
            self.logger.debug(
                f"RFC parser failed, using best-effort parsing: {parent_result.error}",
            )
            return self._parse_objectclass_relaxed(oc_definition)

        def _parse_objectclass_relaxed(
            self,
            oc_definition: str,
        ) -> p.Result[m.Ldif.SchemaObjectClass]:
            """Parse objectClass with relaxed/best-effort parsing using utilities."""
            oid = self._extract_oid_with_fallback_patterns(oc_definition)
            if not oid:
                return r[m.Ldif.SchemaObjectClass].fail(
                    "Failed to extract OID from objectClass definition",
                )
            name = u.Ldif.extract_optional_field(
                oc_definition,
                "\\bNAME\\s+(?:'([^']+)'|\\(([^)]+)\\))\\b",
                default=oid,
            )
            desc = u.Ldif.extract_optional_field(
                oc_definition,
                "\\bDESC\\s+'([^']+)'\\b",
            )
            sup = self._extract_sup_from_objectclass(oc_definition)
            kind_match = c.Ldif.SCHEMA_OBJECTCLASS_KIND_RE.search(oc_definition)
            kind = (
                kind_match.group(1).upper()
                if kind_match
                else c.Ldif.SchemaKind.STRUCTURAL.value
            )
            must, may = self._extract_must_may_from_objectclass(oc_definition)
            metadata = m.Ldif.ServerMetadata.model_validate({
                "server_type": self._get_server_type(),
                "extensions": m.Ldif.DynamicMetadata.model_validate({
                    "original_format": oc_definition.strip(),
                    "schema_source_server": "relaxed",
                }),
            })
            objectclass_name = name or oid
            return r[m.Ldif.SchemaObjectClass].ok(
                m.Ldif.SchemaObjectClass.model_validate({
                    "name": objectclass_name,
                    "oid": oid,
                    "desc": desc,
                    "sup": sup,
                    "kind": kind,
                    "must": must,
                    "may": may,
                    "metadata": metadata,
                }),
            )

        @override
        def _write_attribute(self, attr_data: m.Ldif.SchemaAttribute) -> p.Result[str]:
            """Write attribute to RFC format - stringify in relaxed mode."""
            parent_result = super()._write_attribute(attr_data)
            if parent_result.success:
                return parent_result
            extensions = attr_data.metadata.extensions if attr_data.metadata else None
            source_server = (
                extensions.schema_source_server if extensions is not None else None
            )
            original_format = (
                extensions.original_format if extensions is not None else None
            )
            if source_server == "relaxed" and original_format:
                return r[str].ok(original_format)
            if not attr_data.oid:
                return r[str].fail("Attribute OID is required for writing")
            attr_name: str
            attr_name = attr_data.name or attr_data.oid
            return r[str].ok(f"( {attr_data.oid} NAME '{attr_name}' )")

        @override
        def _write_objectclass(
            self,
            oc_data: m.Ldif.SchemaObjectClass,
        ) -> p.Result[str]:
            """Write objectClass to RFC format - stringify in relaxed mode."""
            parent_result = super()._write_objectclass(oc_data)
            if parent_result.success:
                return parent_result
            extensions = oc_data.metadata.extensions if oc_data.metadata else None
            source_server = (
                extensions.schema_source_server if extensions is not None else None
            )
            original_format = (
                extensions.original_format if extensions is not None else None
            )
            if source_server == "relaxed" and original_format:
                return r[str].ok(original_format)
            if not oc_data.oid:
                return r[str].fail("ObjectClass OID is required for writing")
            oc_name: str
            oc_name = oc_data.name or oc_data.oid
            oc_kind: str
            oc_kind = oc_data.kind or c.Ldif.SchemaKind.STRUCTURAL.value
            return r[str].ok(f"( {oc_data.oid} NAME '{oc_name}' {oc_kind} )")

    class Acl(FlextLdifServersRfc.Acl):
        """Relaxed ACL server for lenient LDIF processing."""

        @override
        def can_handle(self, acl_line: str | m.Ldif.Acl) -> bool:
            """Check if this is a relaxed ACL (public method)."""
            if isinstance(acl_line, str):
                return self.can_handle_acl(acl_line)
            return self.can_handle_acl(acl_line)

        @override
        def can_handle_acl(
            self,
            acl_line: str | m.Ldif.Acl | t.JsonValue,
        ) -> bool:
            """Accept any ACL line in relaxed mode."""
            _ = acl_line
            return True

        @override
        def can_handle_attribute(self, attribute: m.Ldif.SchemaAttribute) -> bool:
            """Check if this ACL server should be aware of a specific attribute definition."""
            _ = attribute
            return True

        @override
        def can_handle_objectclass(self, objectclass: m.Ldif.SchemaObjectClass) -> bool:
            """Check if this ACL server should be aware of a specific objectClass definition."""
            _ = objectclass
            return True

        @override
        def _parse_acl(self, acl_line: str) -> p.Result[m.Ldif.Acl]:
            """Parse ACL with best-effort approach."""
            if not acl_line or not acl_line.strip():
                return r[m.Ldif.Acl].fail("ACL line cannot be empty")
            try:
                return self._parse_relaxed_acl(acl_line)
            except c.Ldif.EXC_LDIF_PARSE as e:
                self.logger.debug(
                    "Relaxed ACL parse failed: %s",
                    e,
                )
                return r[m.Ldif.Acl].fail(f"Failed to parse ACL: {e}")

        def _parse_relaxed_acl(self, acl_line: str) -> p.Result[m.Ldif.Acl]:
            """Parse ACL using RFC first, then relaxed fallback."""
            parent_result = super()._parse_acl(acl_line)
            if parent_result.success:
                updated_acl = self._with_relaxed_acl_metadata(
                    parent_result.value,
                    acl_line,
                )
                return r[m.Ldif.Acl].ok(updated_acl)
            relaxed_acl = self._build_relaxed_acl(acl_line)
            return r[m.Ldif.Acl].ok(relaxed_acl)

        def _with_relaxed_acl_metadata(
            self,
            acl: m.Ldif.Acl,
            acl_line: str,
        ) -> m.Ldif.Acl:
            """Attach relaxed metadata to an ACL."""
            if not acl.metadata:
                acl_with_metadata: m.Ldif.Acl = acl.model_copy(
                    update={
                        "metadata": m.Ldif.ServerMetadata.model_validate({
                            "server_type": self._get_server_type(),
                            "extensions": m.Ldif.DynamicMetadata.model_validate({
                                "original_format": acl_line.strip(),
                            }),
                        }),
                    },
                )
                return acl_with_metadata
            updated_extensions = acl.metadata.extensions or m.Ldif.DynamicMetadata()
            updated_metadata = acl.metadata.model_copy(
                update={
                    "server_type": self._get_server_type(),
                    "extensions": updated_extensions,
                },
            )
            updated_acl: m.Ldif.Acl = acl.model_copy(
                update={"metadata": updated_metadata},
            )
            return updated_acl

        def _build_relaxed_acl(self, acl_line: str) -> m.Ldif.Acl:
            """Build relaxed ACL fallback model."""
            relaxed_acl: m.Ldif.Acl = m.Ldif.Acl.model_validate({
                "name": FlextLdifServersRelaxed.Constants.ACL_DEFAULT_NAME,
                "target": m.Ldif.AclTarget.model_validate({
                    "target_dn": FlextLdifServersRelaxed.Constants.ACL_DEFAULT_TARGET_DN,
                    "attributes": [],
                }),
                "subject": m.Ldif.AclSubject.model_validate({
                    "subject_type": "all",
                    "subject_value": FlextLdifServersRelaxed.Constants.ACL_DEFAULT_SUBJECT_VALUE,
                }),
                "permissions": m.Ldif.AclPermissions.model_validate({}),
                "server_type": self._get_server_type(),
                "validation_violations": [],
                "raw_line": acl_line,
                "raw_acl": acl_line,
                "metadata": m.Ldif.ServerMetadata.model_validate({
                    "server_type": self._get_server_type(),
                    "extensions": m.Ldif.DynamicMetadata.model_validate({
                        "original_format": acl_line.strip(),
                    }),
                }),
            })
            return relaxed_acl

        @override
        def _write_acl(self, acl_data: m.Ldif.Acl) -> p.Result[str]:
            """Write ACL to RFC format - stringify in relaxed mode."""
            parent_result = super()._write_acl(acl_data)
            if parent_result.success:
                return parent_result
            if acl_data.raw_acl:
                return r[str].ok(acl_data.raw_acl)
            acl_name = (
                acl_data.name or FlextLdifServersRelaxed.Constants.ACL_DEFAULT_NAME
            )
            return r[str].ok(
                f"{FlextLdifServersRelaxed.Constants.ACL_WRITE_PREFIX}{acl_name}",
            )

    class Entry(FlextLdifServersRfc.Entry):
        """Relaxed entry server for lenient LDIF processing."""

        @override
        def can_handle(
            self,
            entry_dn: str,
            attributes: t.MutableStrSequenceMapping,
        ) -> bool:
            """Accept any entry in relaxed mode."""
            _ = entry_dn
            _ = attributes
            return True

        @override
        def can_handle_attribute(self, attribute: m.Ldif.SchemaAttribute) -> bool:
            """Check if this Entry server has special handling for an attribute definition."""
            _ = attribute
            return True

        @override
        def can_handle_objectclass(self, objectclass: m.Ldif.SchemaObjectClass) -> bool:
            """Check if this Entry server has special handling for an objectClass definition."""
            _ = objectclass
            return True

        def normalize_dn(self, dn: str) -> p.Result[str]:
            """Normalize DN using RFC 4514 compliant utility."""
            if not dn or not dn.strip():
                return r[str].fail("DN cannot be empty")
            try:
                norm_result = u.Ldif.norm(dn)
                if norm_result.success:
                    return r[str].ok(norm_result.value)
                return r[str].fail(
                    f"DN normalization failed for DN: {dn}: {norm_result.error}",
                )
            except c.Ldif.EXC_LDIF_PARSE as e:
                self.logger.debug(
                    "DN normalization exception: %s",
                    e,
                )
                return r[str].fail_op("DN normalization", e)

        def process_entry(self, entry: m.Ldif.Entry) -> p.Result[m.Ldif.Entry]:
            """Process entry for relaxed mode."""
            return r[m.Ldif.Entry].ok(entry)

        def _adapted_parse_entry_relaxed(
            self,
            entry_content: str,
        ) -> p.Result[m.Ldif.Entry]:
            """Parse entry content in relaxed mode (extracted from _parse_content)."""
            dn: str = ""
            attrs: MutableMapping[str, t.MutableSequenceOf[str | bytes]] = {}
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
                return r[m.Ldif.Entry].fail("No DN found in entry")
            return self._parse_entry(dn, attrs)

        @override
        def _parse_content(
            self,
            ldif_content: str,
        ) -> p.Result[t.MutableSequenceOf[m.Ldif.Entry]]:
            """Parse raw LDIF content string into Entry models (internal)."""
            parent_result = super()._parse_content(ldif_content)
            if parent_result.success:
                return parent_result
            self.logger.debug(
                f"RFC parser failed, using relaxed mode: {parent_result.error}",
            )
            try:
                return self._parse_relaxed_content(ldif_content)
            except c.Ldif.EXC_LDIF_PARSE as error:
                self.logger.exception(
                    "Failed to parse content",
                    server_type=self._get_server_type(),
                )
                return r[t.MutableSequenceOf[m.Ldif.Entry]].fail(
                    f"Failed to parse content: {error}",
                )

        def _parse_relaxed_content(
            self,
            ldif_content: str,
        ) -> p.Result[t.MutableSequenceOf[m.Ldif.Entry]]:
            """Parse raw LDIF content with relaxed record splitting."""
            entries: t.MutableSequenceOf[m.Ldif.Entry] = []
            raw_entries = ldif_content.strip().split("\n\n")
            successful = 0
            failed = 0
            for raw_entry in raw_entries:
                processed_entry = self._prepare_relaxed_raw_entry(raw_entry)
                if processed_entry is None:
                    continue
                result = self._adapted_parse_entry_relaxed(processed_entry)
                if result.success:
                    successful += 1
                    entries.append(result.value)
                    continue
                failed += 1
                self.logger.warning(
                    "Failed to parse entry",
                    error=str(result.error),
                    server_type=self._get_server_type(),
                )
            self.logger.debug(
                "LDIF content parse stats",
                total_entries=len(raw_entries),
                successful=successful,
                failed=failed,
            )
            return r[t.MutableSequenceOf[m.Ldif.Entry]].ok(entries)

        @staticmethod
        def _prepare_relaxed_raw_entry(raw_entry: str) -> str | None:
            """Normalize one raw relaxed LDIF entry block."""
            if not raw_entry.strip():
                return None
            lines = raw_entry.strip().split("\n")
            processed_entry = raw_entry.strip()
            if lines and lines[0].lower().startswith("version:"):
                lines = lines[1:]
                if not lines:
                    return None
                processed_entry = "\n".join(lines)
            return processed_entry

        def _parse_entry(
            self,
            entry_dn: str,
            entry_attrs: MutableMapping[str, t.MutableSequenceOf[str | bytes]],
        ) -> p.Result[m.Ldif.Entry]:
            """Parse entry with best-effort approach."""
            try:
                return self._parse_relaxed_entry(entry_dn, entry_attrs)
            except c.Ldif.EXC_LDIF_PARSE as e:
                self.logger.debug(
                    "Relaxed entry creation failed: %s",
                    e,
                )
                return r[m.Ldif.Entry].fail(f"Failed to parse entry: {e}")

        def _parse_relaxed_entry(
            self,
            entry_dn: str,
            entry_attrs: MutableMapping[str, t.MutableSequenceOf[str | bytes]],
        ) -> p.Result[m.Ldif.Entry]:
            """Build an entry model from relaxed raw entry components."""
            if not entry_dn or not entry_dn.strip():
                return r[m.Ldif.Entry].fail("Entry DN cannot be empty")
            effective_dn = m.Ldif.DN.model_validate({
                "value": entry_dn.strip(),
                "metadata": {},
            })
            ldif_attrs = m.Ldif.Attributes.model_validate({
                "attributes": self._decode_relaxed_attributes(entry_attrs),
                "attribute_metadata": {},
                "metadata": None,
            })
            entry = m.Ldif.Entry(
                dn=effective_dn,
                attributes=ldif_attrs,
                changetype=None,
                metadata=self._build_relaxed_entry_metadata(entry_dn, entry_attrs),
            )
            return r[m.Ldif.Entry].ok(entry)

        @staticmethod
        def _decode_relaxed_attributes(
            entry_attrs: MutableMapping[str, t.MutableSequenceOf[str | bytes]],
        ) -> t.MutableStrSequenceMapping:
            """Decode relaxed entry attributes to string values."""
            attr_dict: t.MutableStrSequenceMapping = {}
            for attr_key, attr_value in entry_attrs.items():
                converted_list: t.MutableSequenceOf[str] = []
                for value in attr_value:
                    if isinstance(value, str):
                        converted_list.append(value)
                    else:
                        converted_list.append(
                            value.decode(
                                FlextLdifServersRelaxed.Constants.ENCODING_UTF8,
                                errors=FlextLdifServersRelaxed.Constants.ENCODING_ERROR_HANDLING,
                            ),
                        )
                attr_dict[attr_key] = converted_list
            return attr_dict

        @staticmethod
        def _build_relaxed_entry_metadata(
            entry_dn: str,
            entry_attrs: MutableMapping[str, t.MutableSequenceOf[str | bytes]],
        ) -> m.Ldif.ServerMetadata:
            """Build metadata for relaxed entry parsing."""
            original_attribute_case: t.MutableStrMapping = {}
            for attr_name in entry_attrs:
                attr_str = attr_name
                if attr_str.lower() == "objectclass":
                    original_attribute_case["objectClass"] = attr_str
            format_details = m.Ldif.FormatDetails(
                dn_line=entry_dn,
                spacing=entry_dn,
                syntax=None,
                encoding=None,
                trailing_info=None,
            )
            case_metadata = m.Ldif.DynamicMetadata.model_validate(
                original_attribute_case,
            )
            metadata: m.Ldif.ServerMetadata = m.Ldif.ServerMetadata.model_validate({
                "server_type": "relaxed",
                "original_format_details": format_details,
                "original_attribute_case": case_metadata,
                "extensions": m.Ldif.DynamicMetadata.model_validate({
                    "server_type": "relaxed",
                    "relaxed_mode": True,
                }),
            })
            return metadata

        @override
        def _write_entry(self, entry_data: m.Ldif.Entry) -> p.Result[str]:
            """Write Entry model to RFC-compliant LDIF string format (internal)."""
            parent_result = super()._write_entry(entry_data)
            if parent_result.success:
                return parent_result
            self.logger.debug(
                f"RFC write failed, using relaxed mode: {parent_result.error}",
            )
            try:
                return self._write_relaxed_entry(entry_data)
            except c.Ldif.EXC_LDIF_PARSE as e:
                self.logger.debug("Write entry failed: %s", e)
                return r[str].fail(f"Failed to write entry: {e}")

        @staticmethod
        def _write_relaxed_entry(entry_data: m.Ldif.Entry) -> p.Result[str]:
            """Write entry in relaxed LDIF format."""
            ldif_lines: t.MutableSequenceOf[str] = []
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
            if ldif_text and (
                not ldif_text.endswith(FlextLdifServersRelaxed.Constants.LDIF_NEWLINE)
            ):
                ldif_text += FlextLdifServersRelaxed.Constants.LDIF_NEWLINE
            return r[str].ok(ldif_text)


__all__: list[str] = ["FlextLdifServersRelaxed"]
