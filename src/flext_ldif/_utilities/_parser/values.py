"""LDIF value decoding utilities.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import base64

from flext_cli import r

from flext_ldif import c, p
from flext_ldif._models import FlextLdifModelsDomainEntryControl


class FlextLdifUtilitiesParserValues:
    """Decode LDIF value specs and control payloads."""

    @staticmethod
    def decode_value(remainder: str) -> tuple[str, c.Ldif.ValueOrigin, str | None]:
        """Decode an LDIF value-spec preserving origin details.

        Only the RFC 2849 FILL (spaces) after the separator is dropped; every
        other character of the value is kept. A base64 payload decodes
        byte-exact: bytes that are not UTF-8 stay in the value through
        ``c.Ldif.LOSSLESS_BYTES_ERRORS`` (encode the value with the same
        handler to get them back).

        Returns:
            The resulting ``tuple[str, c.Ldif.ValueOrigin, str | None]``.

        Raises:
            ValueError: When a base64 payload is not valid base64.

        """
        fill = c.Ldif.VALUE_FILL
        payload = remainder.lstrip(fill)
        if payload.startswith(":"):
            encoded_value = payload[1:].lstrip(fill)
            try:
                decoded_bytes = base64.b64decode(encoded_value, validate=True)
            except ValueError as exc:
                msg = f"Invalid base64 value {encoded_value!r}: {exc}"
                raise ValueError(msg) from exc
            decoded_value = decoded_bytes.decode(
                c.Ldif.DEFAULT_ENCODING,
                errors=c.Ldif.LOSSLESS_BYTES_ERRORS,
            )
            return (decoded_value, c.Ldif.ValueOrigin.BASE64, encoded_value)
        if payload.startswith("<"):
            url_value = payload[1:].lstrip(fill)
            origin = (
                c.Ldif.ValueOrigin.FILE
                if url_value.startswith("file://")
                else c.Ldif.ValueOrigin.URL
            )
            return (url_value, origin, url_value)
        return (payload, c.Ldif.ValueOrigin.PLAIN, payload)

    @staticmethod
    def build_control(payload: str) -> FlextLdifModelsDomainEntryControl.Control:
        """Parse RFC 2849 control payload into a structured model.

        Returns:
            The resulting ``FlextLdifModelsDomainEntryControl.Control``.

        """
        minimum_control_tokens = 2
        control_tokens_with_value = 3
        tokens = payload.split(maxsplit=2)
        control_type = tokens[0] if tokens else ""
        criticality: bool | None = None
        value: str | None = None
        value_origin: c.Ldif.ValueOrigin | None = None
        raw_value: str | None = None
        value_token: str | None = None
        if len(tokens) >= minimum_control_tokens:
            if tokens[1].lower() in {
                c.ParserBooleanToken.TRUE,
                c.ParserBooleanToken.FALSE,
            }:
                criticality = tokens[1].lower() == c.ParserBooleanToken.TRUE
                if len(tokens) == control_tokens_with_value:
                    value_token = tokens[2]
            else:
                value_token = " ".join(tokens[1:])
        if value_token is not None:
            value, value_origin, raw_value = (
                FlextLdifUtilitiesParserValues.decode_value(
                    value_token,
                )
            )
        return FlextLdifModelsDomainEntryControl.Control(
            control_type=control_type,
            criticality=criticality,
            control_value=value,
            control_value_origin=value_origin,
            raw_value=raw_value,
        )

    @staticmethod
    def parse_attribute_line(line: str) -> p.Result[tuple[str, str, bool]]:
        """Parse LDIF attribute line into name, value, and base64 flag.

        Returns:
            The resulting ``p.Result[tuple[str, str, bool]]``.

        """
        if ":" not in line:
            return r[tuple[str, str, bool]].fail(
                f"No colon separator in line: {line!r}",
            )
        attr_name, attr_value = line.split(":", 1)
        attr_name = attr_name.strip()
        attr_value = attr_value.strip()
        is_base64 = False
        if attr_value.startswith(":"):
            is_base64 = True
            attr_value = attr_value[1:].strip()
        return r[tuple[str, str, bool]].ok((attr_name, attr_value, is_base64))


__all__: list[str] = ["FlextLdifUtilitiesParserValues"]
