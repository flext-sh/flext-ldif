"""Relaxed entry server for lenient LDIF processing.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import MutableMapping
from typing import override

from flext_ldif import c, m, p, r, t, u
from flext_ldif.servers.relaxed_constants import FlextLdifServersRelaxedConstants
from flext_ldif.servers.rfc import FlextLdifServersRfc


class FlextLdifServersRelaxedEntry(FlextLdifServersRfc.Entry):
    """Relaxed entry server for lenient LDIF processing."""

    @override
    def can_handle(
        self,
        entry_dn: str,
        attributes: t.MutableStrSequenceMapping,
    ) -> bool:
        """Accept any entry in relaxed mode.

        Returns:
            The resulting ``bool``.
        """
        _ = entry_dn
        _ = attributes
        return True

    @override
    def can_handle_attribute(self, attribute: m.Ldif.SchemaAttribute) -> bool:
        """Check if this Entry server has special attribute handling.

        Returns:
            The resulting ``bool``.
        """
        _ = attribute
        return True

    @override
    def can_handle_objectclass(self, objectclass: m.Ldif.SchemaObjectClass) -> bool:
        """Check if this Entry server has special objectClass handling.

        Returns:
            The resulting ``bool``.
        """
        _ = objectclass
        return True

    def normalize_dn(self, dn: str) -> p.Result[str]:
        """Normalize DN using RFC 4514 compliant utility.

        Returns:
            The resulting ``p.Result[str]``.
        """
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
            self.logger.debug("DN normalization exception: %s", e)
            return r[str].fail_op("DN normalization", e)

    @staticmethod
    def process_entry(entry: m.Ldif.Entry) -> p.Result[m.Ldif.Entry]:
        """Process entry for relaxed mode.

        Returns:
            The resulting ``p.Result[m.Ldif.Entry]``.
        """
        return r[m.Ldif.Entry].ok(entry)

    def _adapted_parse_entry_relaxed(
        self,
        entry_content: str,
    ) -> p.Result[m.Ldif.Entry]:
        """Parse entry content in relaxed mode (extracted from _parse_content).

        Returns:
            The resulting ``p.Result[m.Ldif.Entry]``.
        """
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
        """Parse raw LDIF content string into Entry models (internal).

        Returns:
            The resulting ``p.Result[t.MutableSequenceOf[m.Ldif.Entry]]``.
        """
        parent_result = super()._parse_content(ldif_content)
        if parent_result.success:
            return parent_result
        self.logger.debug(
            "RFC parser failed, using relaxed mode: %s", parent_result.error,
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
                exception=error,
            )

    def _parse_relaxed_content(
        self,
        ldif_content: str,
    ) -> p.Result[t.MutableSequenceOf[m.Ldif.Entry]]:
        """Parse raw LDIF content with relaxed record splitting.

        Returns:
            The resulting ``p.Result[t.MutableSequenceOf[m.Ldif.Entry]]``.
        """
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
        """Normalize one raw relaxed LDIF entry block.

        Returns:
            The resulting ``str | None``.
        """
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
        """Parse entry with best-effort approach.

        Returns:
            The resulting ``p.Result[m.Ldif.Entry]``.
        """
        try:
            return self._parse_relaxed_entry(entry_dn, entry_attrs)
        except c.Ldif.EXC_LDIF_PARSE as e:
            self.logger.debug("Relaxed entry creation failed: %s", e)
            return r[m.Ldif.Entry].fail(f"Failed to parse entry: {e}", exception=e)

    def _parse_relaxed_entry(
        self,
        entry_dn: str,
        entry_attrs: MutableMapping[str, t.MutableSequenceOf[str | bytes]],
    ) -> p.Result[m.Ldif.Entry]:
        """Build an entry model from relaxed raw entry components.

        Returns:
            The resulting ``p.Result[m.Ldif.Entry]``.
        """
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
        """Decode relaxed entry attributes to string values.

        Returns:
            The resulting ``t.MutableStrSequenceMapping``.
        """
        attr_dict: t.MutableStrSequenceMapping = {}
        for attr_key, attr_value in entry_attrs.items():
            converted_list: t.MutableSequenceOf[str] = []
            for value in attr_value:
                if isinstance(value, str):
                    converted_list.append(value)
                else:
                    converted_list.append(
                        value.decode(
                            FlextLdifServersRelaxedConstants.ENCODING_UTF8,
                            errors=FlextLdifServersRelaxedConstants.ENCODING_ERROR_HANDLING,
                        ),
                    )
            attr_dict[attr_key] = converted_list
        return attr_dict

    @staticmethod
    def _build_relaxed_entry_metadata(
        entry_dn: str,
        entry_attrs: MutableMapping[str, t.MutableSequenceOf[str | bytes]],
    ) -> m.Ldif.ServerMetadata:
        """Build metadata for relaxed entry parsing.

        Returns:
            The resulting ``m.Ldif.ServerMetadata``.
        """
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
        metadata: m.Ldif.ServerMetadata = m.Ldif.ServerMetadata.model_validate({
            "server_type": "relaxed",
            "original_format_details": format_details,
            "original_attribute_case": original_attribute_case,
            "extensions": {"server_type": "relaxed", "relaxed_mode": True},
        })
        return metadata

    @override
    def _write_entry(self, entry_data: m.Ldif.Entry) -> p.Result[str]:
        """Write Entry model to RFC-compliant LDIF string format (internal).

        Returns:
            The resulting ``p.Result[str]``.
        """
        parent_result = super()._write_entry(entry_data)
        if parent_result.success:
            return parent_result
        self.logger.debug(
            "RFC write failed, using relaxed mode: %s", parent_result.error,
        )
        try:
            return self._write_relaxed_entry(entry_data)
        except c.Ldif.EXC_LDIF_PARSE as e:
            self.logger.debug("Write entry failed: %s", e)
            return r[str].fail(f"Failed to write entry: {e}", exception=e)

    @staticmethod
    def _write_relaxed_entry(entry_data: m.Ldif.Entry) -> p.Result[str]:
        """Write entry in relaxed LDIF format.

        Returns:
            The resulting ``p.Result[str]``.
        """
        ldif_lines: t.MutableSequenceOf[str] = []
        if not entry_data.dn or not entry_data.dn.value:
            return r[str].fail("Entry DN is required for LDIF output")
        ldif_lines.append(
            f"{FlextLdifServersRelaxedConstants.LDIF_DN_PREFIX}{entry_data.dn.value}",
        )
        if entry_data.attributes and entry_data.attributes.attributes:
            for attr_name, attr_values in entry_data.attributes.attributes.items():
                ldif_lines.extend(
                    f"{attr_name}{FlextLdifServersRelaxedConstants.LDIF_ATTR_SEPARATOR}{value}"
                    for value in attr_values
                )
        ldif_text = FlextLdifServersRelaxedConstants.LDIF_JOIN_SEPARATOR.join(
            ldif_lines,
        )
        if ldif_text and (
            not ldif_text.endswith(FlextLdifServersRelaxedConstants.LDIF_NEWLINE)
        ):
            ldif_text += FlextLdifServersRelaxedConstants.LDIF_NEWLINE
        return r[str].ok(ldif_text)


__all__: list[str] = ["FlextLdifServersRelaxedEntry"]
