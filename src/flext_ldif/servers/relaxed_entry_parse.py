"""Relaxed entry server — lenient LDIF parse side.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import MutableMapping
from typing import override

from flext_ldif import c, m, p, r, t, u
from flext_ldif.servers._relaxed import FlextLdifServersRelaxedConstants
from flext_ldif.servers._rfc import FlextLdifServersRfcEntry


class FlextLdifServersRelaxedEntryParse(FlextLdifServersRfcEntry):
    """Relaxed entry parse side for lenient LDIF processing."""

    def normalize_dn(self, dn: str) -> p.Result[str]:
        """Normalize a DN using the RFC 4514 compliant utility.

        Args:
            dn: DN string to normalize.

        Returns:
            Result carrying the normalized DN, or a failure.

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

    def _adapted_parse_entry_relaxed(
        self,
        entry_content: str,
    ) -> p.Result[m.Ldif.Entry]:
        """Parse one entry block in relaxed mode.

        Args:
            entry_content: Unfolded entry block text.

        Returns:
            Result carrying the parsed entry, or a failure.

        """
        dn, attrs = self._scan_relaxed_entry_lines(entry_content)
        if not dn:
            return r[m.Ldif.Entry].fail("No DN found in entry")
        return self._parse_entry(dn, attrs)

    @classmethod
    def _scan_relaxed_entry_lines(
        cls,
        entry_content: str,
    ) -> tuple[str, MutableMapping[str, t.MutableSequenceOf[str | bytes]]]:
        """Scan relaxed entry content into its DN and raw attribute values.

        Args:
            entry_content: Entry block text to scan line by line.

        Returns:
            Pair of the DN and raw attribute names mapped to values.

        """
        dn: str = ""
        attrs: MutableMapping[str, t.MutableSequenceOf[str | bytes]] = {}
        for raw_line in entry_content.split("\n"):
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            line_dn = cls._absorb_relaxed_line(line, attrs)
            if line_dn is not None:
                dn = line_dn
        return (dn, attrs)

    @classmethod
    def _absorb_relaxed_line(
        cls,
        line: str,
        attrs: MutableMapping[str, t.MutableSequenceOf[str | bytes]],
    ) -> str | None:
        """Absorb one non-comment line; return its DN value for DN lines.

        Args:
            line: Stripped, non-comment entry line.
            attrs: Attribute mapping the line appends to.

        Returns:
            The DN value when the line is a DN line, else None.

        """
        if line.startswith(" ") and attrs:
            cls._fold_relaxed_continuation_line(line, attrs)
            return None
        if ":" not in line:
            return None
        key, _, value = line.partition(":")
        stripped_key = key.strip()
        stripped_value = value.strip()
        if stripped_key.lower() == "dn":
            return stripped_value
        if stripped_key not in attrs:
            attrs[stripped_key] = []
        attrs[stripped_key].append(stripped_value)
        return None

    @staticmethod
    def _fold_relaxed_continuation_line(
        line: str,
        attrs: MutableMapping[str, t.MutableSequenceOf[str | bytes]],
    ) -> None:
        """Fold one continuation line into the last attribute value."""
        last_key = list(attrs.keys())[-1]
        if attrs[last_key]:
            attrs[last_key][-1] = str(attrs[last_key][-1]) + line[1:]

    @override
    def _parse_content(
        self,
        ldif_content: str,
    ) -> p.Result[t.MutableSequenceOf[m.Ldif.Entry]]:
        """Parse raw LDIF content into entry models.

        Falls back to relaxed parsing when the RFC baseline fails.

        Args:
            ldif_content: Raw LDIF content text.

        Returns:
            Result carrying the parsed entries, or a failure.

        """
        parent_result = super()._parse_content(ldif_content)
        if parent_result.success:
            return parent_result
        self.logger.debug(
            "RFC parser failed, using relaxed mode: %s",
            parent_result.error,
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

        Blank-line-separated blocks are parsed individually; failed blocks
        are logged and skipped.

        Args:
            ldif_content: Raw LDIF content text.

        Returns:
            Result carrying the successfully parsed entries.

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
        """Strip the version header from one raw LDIF entry block.

        Args:
            raw_entry: Raw entry block text.

        Returns:
            The block without a leading version line, or None when empty.

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
        """Parse one entry with best-effort relaxed handling.

        Args:
            entry_dn: Distinguished name of the entry.
            entry_attrs: Attribute names mapped to raw values.

        Returns:
            Result carrying the parsed entry, or a failure.

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

        Args:
            entry_dn: Distinguished name of the entry.
            entry_attrs: Attribute names mapped to raw values.

        Returns:
            Result carrying the built entry, or a failure.

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
        """Decode relaxed entry attribute values to strings.

        Args:
            entry_attrs: Attribute names mapped to string or byte values.

        Returns:
            Attribute names mapped to decoded string values.

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
        """Build relaxed-mode metadata for a parsed entry.

        Preserves the original DN line and objectClass attribute casing.

        Args:
            entry_dn: Distinguished name of the entry.
            entry_attrs: Attribute names mapped to raw values.

        Returns:
            Server metadata for the relaxed parse.

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


__all__: list[str] = ["FlextLdifServersRelaxedEntryParse"]
