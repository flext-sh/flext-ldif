"""RFC schema server — JSON/schema value coercion helpers.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import ClassVar

from flext_ldif import c, p, r, t, u
from flext_ldif.servers._base import FlextLdifServersBaseSchema


class FlextLdifServersRfcSchemaValuesMixin(FlextLdifServersBaseSchema):
    """Coerce raw JSON payloads into typed RFC schema values."""

    _module_logger: ClassVar[p.Logger] = u.fetch_logger(__name__)

    @classmethod
    def _extract_syntax_validation_error(cls, value: t.JsonValue | None) -> str | None:
        syntax_validation = cls._coerce_dynamic_metadata(value)
        syntax_error = syntax_validation.get("syntax_validation_error")
        return syntax_error if isinstance(syntax_error, str) else None

    @classmethod
    def _to_optional_str_or_list(
        cls,
        value: t.JsonValue | None,
    ) -> str | t.MutableSequenceOf[str] | None:
        if isinstance(value, str):
            return value
        return cls._to_string_list(value)

    @staticmethod
    def _coerce_dynamic_metadata(value: t.JsonValue | None) -> t.MutableJsonMapping:
        # mro-wgwh.5 (agent: kimi-coder) — DynamicMetadata removed: coerce to a plain
        # JSON mapping with the same None/invalid -> {} semantics.
        if isinstance(value, dict):
            return value
        if value is None:
            return {}
        try:
            validated: t.MutableJsonMapping = t.json_dict_adapter().validate_python(
                value,
            )
        except c.ValidationError as exc:
            msg = f"JSON validation failed: {exc}"
            raise TypeError(msg) from exc
        else:
            return validated

    @staticmethod
    def _convert_extensions_for_server(
        metadata: t.Ldif.MetadataInputMapping,
    ) -> t.Ldif.SchemaExtensionsMapping:
        extensions: t.Ldif.SchemaExtensionsMapping = {}
        for key, value in metadata.items():
            json_value: t.JsonPayload | None = value
            if isinstance(json_value, list):
                list_value: t.MutableSequenceOf[str] = [
                    str(item) for item in json_value
                ]
                extensions[key] = list_value
            elif isinstance(json_value, (bool, str)):
                extensions[key] = json_value
            else:
                extensions[key] = str(u.normalize_to_json_value(json_value))
        return extensions

    @staticmethod
    def _to_optional_int(value: t.JsonValue | None) -> int | None:
        json_value: t.JsonPayload | None = value
        if isinstance(json_value, int):
            return json_value
        if json_value is None or not json_value:
            return None
        if isinstance(json_value, Mapping) or (
            isinstance(json_value, Sequence) and not isinstance(json_value, str | bytes)
        ):
            return None
        parsed = FlextLdifServersRfcSchemaValuesMixin._parse_int(json_value)
        if parsed.success:
            parsed_value: int = parsed.value
            return parsed_value
        return None

    @staticmethod
    def _parse_int(json_value: t.JsonPayload) -> p.Result[int]:
        """Parse a JSON scalar into an int, propagating the conversion failure.

        Returns:
            The resulting ``p.Result[int]``.
        """
        try:
            parsed_int = int(str(json_value))
        except c.EXC_TYPE_VALIDATION as exc:
            return r[int].fail(str(exc), exception=exc)
        return r[int].ok(parsed_int)

    @staticmethod
    def _to_optional_str(value: t.JsonValue | None) -> str | None:
        json_value: t.JsonPayload | None = value
        if json_value is None:
            return None
        if isinstance(json_value, Mapping) or (
            isinstance(json_value, Sequence) and not isinstance(json_value, str | bytes)
        ):
            return None
        if isinstance(json_value, str):
            return json_value
        return str(json_value)

    @staticmethod
    def _to_required_value(value: t.JsonValue | None, default: str = "") -> str:
        json_value: t.JsonPayload | None = value
        if json_value is None:
            return default
        if isinstance(json_value, Mapping) or (
            isinstance(json_value, Sequence) and not isinstance(json_value, str | bytes)
        ):
            return default
        if isinstance(json_value, str):
            return json_value
        return str(json_value)

    @staticmethod
    def _to_string_list(value: t.JsonValue | None) -> t.MutableSequenceOf[str] | None:
        json_value: t.JsonPayload | None = value
        if isinstance(json_value, Sequence) and not isinstance(json_value, str | bytes):
            list_value: t.MutableSequenceOf[str] = [str(item) for item in json_value]
            return list_value
        return None


__all__: list[str] = ["FlextLdifServersRfcSchemaValuesMixin"]
