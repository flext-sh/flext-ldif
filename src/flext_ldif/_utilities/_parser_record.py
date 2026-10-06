"""LDIF record parsing utilities.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_core import r
from flext_ldif import FlextLdifModels, c, p, t
from flext_ldif._utilities._parser_metadata import FlextLdifParserMetadataBuilders
from flext_ldif._utilities._parser_values import FlextLdifParserValues

_MODIFY_OPS: t.MutableStrMapping = {
    "add": c.Ldif.ChangeOperation.ADD,
    "delete": c.Ldif.ChangeOperation.DELETE,
    "replace": c.Ldif.ChangeOperation.REPLACE,
    "increment": c.Ldif.ChangeOperation.INCREMENT,
}


class FlextLdifParserRecord:
    """Parse a single unfolded LDIF record into an Entry model."""

    class _RecordState:
        """Mutable accumulation state for one LDIF record parse."""

        __slots__ = (
            "attribute_metadata",
            "attrs",
            "change_operations",
            "changetype",
            "comments",
            "controls",
            "current_change_operation",
            "deleteoldrdn",
            "dn",
            "newrdn",
            "newsuperior",
            "raw_record_lines",
            "record_kind",
        )

        def __init__(self) -> None:
            """Initialize an empty record state."""
            self.dn = ""
            self.attrs: t.MutableStrSequenceMapping = {}
            self.attribute_metadata: dict[str, t.MutableAttributeMapping] = {}
            self.comments: t.MutableSequenceOf[str] = []
            self.raw_record_lines: t.MutableSequenceOf[str] = []
            self.controls: t.MutableSequenceOf[FlextLdifModels.Ldif.Control] = []
            self.change_operations: t.MutableSequenceOf[
                FlextLdifModels.Ldif.ChangeOperation
            ] = []
            self.current_change_operation: (
                FlextLdifModels.Ldif.ChangeOperation | None
            ) = None
            self.changetype: c.Ldif.ChangeType | None = None
            self.record_kind = c.Ldif.RecordKind.CONTENT
            self.newrdn: str | None = None
            self.deleteoldrdn: bool | None = None
            self.newsuperior: str | None = None

    class _DecodedValue:
        """One decoded LDIF value with its origin and raw payload."""

        __slots__ = ("raw_value", "value", "value_origin")

        def __init__(
            self,
            value: str,
            value_origin: c.Ldif.ValueOrigin,
            raw_value: str | None,
        ) -> None:
            """Bind the decode result.

            Args:
                value: The decoded value payload.
                value_origin: The origin annotation of the payload.
                raw_value: The raw base64 payload when the value was encoded.
            """
            self.value = value
            self.value_origin = value_origin
            self.raw_value = raw_value

    @staticmethod
    def finalize_change_operation(
        current_op: FlextLdifModels.Ldif.ChangeOperation | None,
        change_operations: t.MutableSequenceOf[FlextLdifModels.Ldif.ChangeOperation],
    ) -> None:
        """Append a pending modify block when present."""
        if current_op is not None:
            change_operations.append(current_op)

    @staticmethod
    def _handle_changetype_line(state: _RecordState, value: str) -> None:
        """Consume a changetype line, tolerating unknown change types."""
        normalized_change_type = value.lower()
        try:
            state.changetype = c.Ldif.ChangeType(normalized_change_type)
        except ValueError:
            state.changetype = None
            return
        state.record_kind = c.Ldif.RecordKind.CHANGE

    @staticmethod
    def _apply_moddn_field(
        state: _RecordState,
        key_lower: str,
        value: str,
    ) -> bool:
        """Apply a moddn/modrdn payload field.

        Returns:
            Whether the field was consumed.
        """
        if state.changetype not in {
            c.Ldif.ChangeType.MODDN,
            c.Ldif.ChangeType.MODRDN,
        }:
            return False
        if key_lower == "newrdn":
            state.newrdn = value
            return True
        if key_lower == "deleteoldrdn":
            state.deleteoldrdn = value.lower() in {"1", "true", "yes"}
            return True
        if key_lower == "newsuperior":
            state.newsuperior = value
            return True
        return False

    @staticmethod
    def _apply_modify_field(
        state: _RecordState,
        key: str,
        decoded: _DecodedValue,
    ) -> str | None:
        """Apply a modify block line and resolve the attribute name to store.

        Returns:
            The attribute name under which the value belongs, or ``None``
            when the line opened a new operation and nothing is stored.
        """
        key_lower = key.lower()
        if key_lower in _MODIFY_OPS:
            FlextLdifParserRecord.finalize_change_operation(
                state.current_change_operation,
                state.change_operations,
            )
            state.current_change_operation = FlextLdifModels.Ldif.ChangeOperation(
                operation=_MODIFY_OPS[key_lower],
                attribute=decoded.value,
            )
            return None
        if state.current_change_operation is not None:
            state.current_change_operation.values.append(
                FlextLdifModels.Ldif.ChangeOperationValue(
                    value=decoded.value,
                    value_origin=decoded.value_origin,
                    raw_value=decoded.raw_value,
                ),
            )
            return state.current_change_operation.attribute
        return key

    @staticmethod
    def _store_attribute(
        state: _RecordState,
        attribute_name: str,
        decoded: _DecodedValue,
    ) -> None:
        """Store one attribute value with its origin and raw payload metadata."""
        state.attrs.setdefault(attribute_name, []).append(decoded.value)
        metadata = state.attribute_metadata.setdefault(attribute_name, {})
        value_origins = metadata.setdefault("value_origins", [])
        if isinstance(value_origins, list):
            value_origins.append(str(decoded.value_origin))
        if decoded.raw_value is None:
            return
        raw_values = metadata.setdefault("raw_values", [])
        if isinstance(raw_values, list):
            raw_values.append(decoded.raw_value)

    @staticmethod
    def _apply_special_line(
        state: _RecordState,
        key_lower: str,
        remainder: str,
    ) -> bool:
        """Consume control/dn/changetype/moddn lines.

        Returns:
            Whether the line was consumed as a special record line.
        """
        if key_lower == "control":
            state.controls.append(
                FlextLdifParserValues.build_control(remainder.lstrip()),
            )
            return True
        if key_lower == "dn":
            state.dn = remainder
            return True
        if key_lower == "changetype":
            FlextLdifParserRecord._handle_changetype_line(state, remainder)
            return True
        consumed = FlextLdifParserRecord._apply_moddn_field(
            state,
            key_lower,
            remainder,
        )
        return bool(consumed)

    @classmethod
    def _parse_data_line(cls, state: _RecordState, line: str) -> None:
        """Consume one non-separator record line into the state."""
        if ":" not in line:
            return
        key, _, remainder = line.partition(":")
        key = key.strip()
        if cls._apply_special_line(state, key.lower(), remainder):
            return
        decoded = cls._DecodedValue(*FlextLdifParserValues.decode_value(remainder))
        attribute_name = key
        if state.changetype == c.Ldif.ChangeType.MODIFY:
            resolved_name = cls._apply_modify_field(state, key, decoded)
            if resolved_name is None:
                return
            attribute_name = resolved_name
        cls._store_attribute(state, attribute_name, decoded)

    @staticmethod
    def _build_entry(
        state: _RecordState,
    ) -> FlextLdifModels.Ldif.Entry:
        """Build the Entry model from accumulated record state.

        Returns:
            The resulting ``FlextLdifModels.Ldif.Entry``.
        """
        return FlextLdifModels.Ldif.Entry(
            dn=FlextLdifModels.Ldif.DN(value=state.dn.strip()),
            attributes=FlextLdifModels.Ldif.Attributes.model_validate({
                "attributes": state.attrs,
                "attribute_metadata": state.attribute_metadata,
            }),
            record_kind=state.record_kind,
            controls=list(state.controls),
            change_operations=list(state.change_operations),
            changetype=state.changetype,
            newrdn=state.newrdn,
            deleteoldrdn=state.deleteoldrdn,
            newsuperior=state.newsuperior,
            raw_record_lines=list(state.raw_record_lines),
            metadata=FlextLdifParserMetadataBuilders.build_rfc_entry_metadata(
                state.dn.strip(),
                state.raw_record_lines,
                state.comments,
            ),
        )

    @staticmethod
    def parse_ldif_record(
        lines: t.MutableSequenceOf[str],
    ) -> p.Result[FlextLdifModels.Ldif.Entry]:
        """Parse a single unfolded LDIF record into Entry.

        Returns:
            The resulting ``p.Result[FlextLdifModels.Ldif.Entry]``.
        """
        state = FlextLdifParserRecord._RecordState()
        for raw_line in lines:
            line = raw_line.rstrip()
            if not line:
                continue
            if line.startswith("#"):
                state.comments.append(line)
                continue
            state.raw_record_lines.append(line)
            if line == "-":
                FlextLdifParserRecord.finalize_change_operation(
                    state.current_change_operation,
                    state.change_operations,
                )
                state.current_change_operation = None
                continue
            FlextLdifParserRecord._parse_data_line(state, line)
        FlextLdifParserRecord.finalize_change_operation(
            state.current_change_operation,
            state.change_operations,
        )
        if not state.dn:
            return r[FlextLdifModels.Ldif.Entry].fail("No DN found in entry")
        try:
            entry = FlextLdifParserRecord._build_entry(state)
            return r[FlextLdifModels.Ldif.Entry].ok(entry)
        except ValueError as exc:
            return r[FlextLdifModels.Ldif.Entry].fail(
                f"Failed to create entry {state.dn}: {exc}",
            )


__all__: list[str] = ["FlextLdifParserRecord"]
