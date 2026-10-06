"""Base entry server — LDIF line emission helpers.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import base64
from collections.abc import Mapping

from flext_ldif import c, m, t, u


class FlextLdifServersEntryLineEmitter:
    """Emit folded LDIF attribute/control lines for one entry write pass."""

    def __init__(
        self,
        entry: m.Ldif.Entry,
        normalize_attribute_names: bool,
        use_original_acl_format_as_name: bool,
        acl_original_format: str | None,
        effective_line_width: int,
    ) -> None:
        """Bind line-emission options and the entry being written."""
        self._entry = entry
        self._normalize_attribute_names = normalize_attribute_names
        self._use_original_acl_format_as_name = use_original_acl_format_as_name
        self._acl_original_format = acl_original_format
        self._effective_line_width = effective_line_width
        self._acl_attribute_names: set[str] = {
            name.lower() for name in c.Ldif.DEFAULT_ACL_ATTRIBUTES
        }

    @property
    def effective_line_width(self) -> int:
        """Effective fold width applied to emitted LDIF lines."""
        return self._effective_line_width

    def emit_attribute_line(
        self,
        attr_name: str,
        value: str,
        *,
        value_origin: str | None = None,
        raw_value: str | None = None,
    ) -> str:
        """Serialize one attribute value to an LDIF line.

        Returns:
            The resulting ``str``.
        """
        effective_name = (
            attr_name.lower() if self._normalize_attribute_names else attr_name
        )
        effective_value = self._maybe_replace_acl_name(attr_name, value)
        if value_origin == c.Ldif.ValueOrigin.BASE64 and raw_value:
            return f"{effective_name}:: {raw_value}"
        if (
            value_origin in {c.Ldif.ValueOrigin.URL, c.Ldif.ValueOrigin.FILE}
            and raw_value
        ):
            return f"{effective_name}:< {raw_value}"
        should_encode = effective_name.lower() in c.Ldif.BINARY_ATTRIBUTE_NAMES
        if should_encode or u.Ldif.needs_base64_encoding(effective_value):
            encoded = base64.b64encode(effective_value.encode("utf-8")).decode(
                "ascii",
            )
            return f"{effective_name}:: {encoded}"
        return f"{effective_name}: {effective_value}"

    def control_line(self, control: m.Ldif.Control) -> str:
        """Serialize RFC 2849 control line.

        Returns:
            The resulting ``str``.
        """
        line = f"control: {control.control_type}"
        if control.criticality is not None:
            line += " true" if control.criticality else " false"
        if control.value is None:
            return line
        if control.value_origin == c.Ldif.ValueOrigin.BASE64:
            encoded_value = control.raw_value or control.value
            return f"{line}:: {encoded_value}"
        if control.value_origin in {
            c.Ldif.ValueOrigin.URL,
            c.Ldif.ValueOrigin.FILE,
        }:
            url_value = control.raw_value or control.value
            return f"{line}:< {url_value}"
        return f"{line}: {control.value}"

    def value_origin_and_raw(
        self,
        attr_name: str,
        value_index: int,
    ) -> tuple[str | None, str | None]:
        """Return preserved value origin and raw payload for an attribute value.

        Returns:
            The resulting ``tuple[str | None, str | None]``.
        """
        if self._entry.attributes is None:
            return (None, None)
        attribute_metadata = self._entry.attributes.attribute_metadata.get(attr_name)
        if not isinstance(attribute_metadata, Mapping):
            return (None, None)
        origins_raw = attribute_metadata.get("value_origins")
        raw_values_raw = attribute_metadata.get("raw_values")
        origin: str | None = None
        raw_value: str | None = None
        if isinstance(origins_raw, list) and value_index < len(origins_raw):
            origin = origins_raw[value_index]
        if isinstance(raw_values_raw, list) and value_index < len(raw_values_raw):
            raw_value = raw_values_raw[value_index]
        return (origin, raw_value)

    def append_attribute_line(
        self,
        output_lines: t.MutableSequenceOf[str],
        attr_name: str,
        line: str,
    ) -> None:
        """Append one attribute line, folding it unless it is an ACL attribute."""
        if attr_name.lower() in self._acl_attribute_names:
            output_lines.append(line)
            return
        output_lines.extend(u.Ldif.fold_line(line, width=self._effective_line_width))

    def _maybe_replace_acl_name(self, attr_name: str, value: str) -> str:
        """Replace the acl name with the preserved original ACL format text.

        Returns:
            The resulting ``str``.
        """
        if not self._use_original_acl_format_as_name:
            return value
        if attr_name.lower() != "aci" or not self._acl_original_format:
            return value
        safe_acl_name = self._acl_original_format.replace('"', "'")
        replaced_acl_name: str = c.Ldif.sub_pattern(
            r'acl\\s+"[^"]*"',
            f'acl "{safe_acl_name}"',
            value,
            count=1,
        )
        return replaced_acl_name


__all__: list[str] = ["FlextLdifServersEntryLineEmitter"]
