"""LDIF entry boolean attribute conversion utilities.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence

from flext_ldif import c, t


class FlextLdifEntryBooleanConversion:
    """Convert boolean attribute values between textual formats."""

    @staticmethod
    def _raw_value_items(
        attr_raw_values: t.MutableSequenceOf[str]
        | t.MutableSequenceOf[bytes]
        | str
        | bytes,
    ) -> Sequence[str | bytes]:
        """Normalize a scalar or sequence attribute payload into items.

        Returns:
            The resulting ``Sequence[str | bytes]``.
        """
        if isinstance(attr_raw_values, str | bytes):
            return [attr_raw_values]
        return attr_raw_values

    @staticmethod
    def _decode_raw_value(raw_item: str | bytes) -> str:
        """Decode a raw value to text, replacing undecodable bytes.

        Returns:
            The resulting ``str``.
        """
        if isinstance(raw_item, bytes):
            return raw_item.decode(c.Ldif.DEFAULT_ENCODING, errors="replace")
        return raw_item

    @staticmethod
    def _convert_boolean_value(
        normalized_value: str,
        format_pair: tuple[str, str],
    ) -> str:
        """Convert one value according to the source/target format pair.

        Returns:
            The resulting ``str``.
        """
        match format_pair:
            case ("0/1", "TRUE/FALSE"):
                return "TRUE" if normalized_value == "1" else "FALSE"
            case ("TRUE/FALSE", "0/1"):
                return "1" if normalized_value.upper() == "TRUE" else "0"
            case _:
                return normalized_value

    @staticmethod
    def convert_boolean_attributes(
        attributes: Mapping[
            str,
            t.MutableSequenceOf[str] | t.MutableSequenceOf[bytes] | str | bytes,
        ],
        boolean_attr_names: set[str],
        *,
        source_format: str = "0/1",
        target_format: str = "TRUE/FALSE",
    ) -> t.MutableStrSequenceMapping:
        """Convert boolean attribute values between formats.

        Returns:
            The resulting ``t.MutableStrSequenceMapping``.
        """
        result: t.MutableStrSequenceMapping = {}
        format_pair = (source_format, target_format)
        normalized_boolean_names = {
            attr_name.lower() for attr_name in boolean_attr_names
        }
        for attr_name in attributes:
            str_values: t.MutableSequenceOf[str] = []
            for raw_item in FlextLdifEntryBooleanConversion._raw_value_items(
                attributes[attr_name],
            ):
                normalized_value = FlextLdifEntryBooleanConversion._decode_raw_value(
                    raw_item,
                )
                if attr_name.lower() in normalized_boolean_names:
                    normalized_value = (
                        FlextLdifEntryBooleanConversion._convert_boolean_value(
                            normalized_value,
                            format_pair,
                        )
                    )
                str_values.append(normalized_value)
            result[attr_name] = str_values
        return result


__all__: list[str] = ["FlextLdifEntryBooleanConversion"]
