"""Normalization/conversion utilities for FLEXT-LDIF."""

from __future__ import annotations

import contextlib
from collections.abc import Callable, Mapping, Sequence
from typing import Self, override

from flext_core import FlextUtilities, r

from flext_ldif import t


class FlextLdifUtilitiesNormalization:
    """Normalization and conversion methods for LDIF utilities."""

    @staticmethod
    def to_config_map_value(value: t.NormalizedValue) -> t.NormalizedValue:
        """Convert value to t.NormalizedValue (general value or str)."""
        if FlextUtilities.is_general_value_type(value):
            return value
        return str(value)

    @staticmethod
    def normalize_container(value: t.NormalizedValue) -> t.NormalizedValue:
        """Normalize a t.NormalizedValue to a canonical form."""
        if FlextUtilities.is_general_value_type(value):
            return value
        return str(value)

    @staticmethod
    def normalize_mapping(
        mapping: Mapping[str, t.NormalizedValue],
    ) -> Mapping[str, t.NormalizedValue]:
        """Normalize a mapping of objects to a standard dict form."""
        normalized: Mapping[str, t.NormalizedValue] = {}
        for key, value in mapping.items():
            normalized[str(key)] = FlextLdifUtilitiesNormalization.normalize_container(
                value,
            )
        return normalized

    class ConvBuilder:
        """Conversion builder for type-safe value conversion (DSL pattern)."""

        def __init__(self, *, value: t.NormalizedValue | None) -> None:
            """Initialize conversion builder with a value."""
            super().__init__()
            self._value: t.NormalizedValue | None = value
            self._default: t.NormalizedValue | None = None
            self._target_type: str | None = None
            self._safe_mode = False

        def build(self) -> t.NormalizedValue | None:
            """Build and return the converted value using parent utilities."""
            if self._value is None:
                return self._default
            if self._target_type == "to_str":
                str_default = ""
                if self._default is not None:
                    with contextlib.suppress(TypeError, ValueError):
                        str_default = str(self._default)
                value_str = str(self._value)
                return value_str or str_default
            if self._target_type == "to_str_list":
                list_default: Sequence[str] = []
                if self._default is not None:
                    if isinstance(self._default, list):
                        list_default = [str(x) for x in self._default]
                    else:
                        default_value = str(self._default)
                        list_default = [default_value] if default_value else []
                match self._value:
                    case list() | tuple() as seq_values:
                        normalized = [str(item) for item in seq_values]
                        return normalized or list_default
                    case _:
                        single = str(self._value)
                        if single:
                            return [single]
                        return list_default
            if self._target_type == "to_int":
                if self._safe_mode:
                    try:
                        return int(str(self._value))
                    except (ValueError, TypeError):
                        return self._default
                return int(str(self._value))
            if self._target_type == "to_bool":
                try:
                    str_val = str(self._value).lower()
                    return str_val in {"true", "1", "yes", "on"}
                except (TypeError, ValueError):
                    return bool(self._value)
            return self._value

        def safe(self) -> Self:
            """Enable safe mode."""
            self._safe_mode = True
            return self

        def str_list(self, default: Sequence[str] | None = None) -> Self:
            """Convert to string list using parent Conversion utilities."""
            self._default = default if default is not None else Sequence[str]()
            self._target_type = "to_str_list"
            return self

        def to_bool(self, *, default: bool = False) -> Self:
            """Convert to bool."""
            self._default = default
            self._target_type = "to_bool"
            return self

        def to_int(self, default: int = 0) -> Self:
            """Convert to int."""
            self._default = default
            self._target_type = "to_int"
            return self

        def to_str(self, default: str = "") -> Self:
            """Convert to string using parent Conversion utilities."""
            self._default = default
            self._target_type = "to_str"
            return self

    @classmethod
    def normalize_list(
        cls,
        value: t.NormalizedValue | r[t.NormalizedValue],
        *,
        default: Sequence[t.NormalizedValue] | None = None,
    ) -> Sequence[t.NormalizedValue]:
        """Normalize to list using FlextUtilities.build() DSL (mnemonic: nl)."""
        extracted_value: t.NormalizedValue | None
        match value:
            case r() as result_value:
                extracted_value = (
                    result_value.value if not result_value.is_failure else None
                )
            case _:
                extracted_value = value
        default_list: Sequence[t.NormalizedValue] = (
            default if default is not None else []
        )
        extracted: t.NormalizedValue = (
            extracted_value if extracted_value is not None else default_list
        )
        ops: Mapping[str, t.NormalizedValue] = {
            "ensure": "list",
            "ensure_default": default_list,
        }
        result = cls.build(
            extracted,
            ops=ops,
        )
        match result:
            case list() as result_list:
                return [cls.to_config_map_value(item) for item in result_list]
            case tuple() as result_tuple:
                return [cls.to_config_map_value(item) for item in result_tuple]
            case _:
                pass
        result_typed = cls.to_config_map_value(result)
        return [result_typed]

    @classmethod
    def normalize_ldif(
        cls,
        value: str | Sequence[str] | tuple[str, ...] | set[str] | frozenset[str],
        other: str
        | Sequence[str]
        | tuple[str, ...]
        | set[str]
        | frozenset[str]
        | None = None,
        *,
        case: str = "lower",
    ) -> str | Sequence[str] | set[str] | bool:
        """Normalize for LDIF comparison (mnemonic: nz)."""

        def normalize_single(v: str) -> str:
            if case == "lower":
                return v.lower()
            if case == "upper":
                return v.upper()
            return v

        if other is not None:
            match (value, other):
                case [str() as value_str, str() as other_str]:
                    return normalize_single(value_str) == normalize_single(
                        other_str,
                    )
                case _:
                    pass
        match value:
            case str() as value_str:
                return normalize_single(value_str)
            case list() | tuple() as seq_value:
                return [normalize_single(str(v)) for v in seq_value]
            case set() | frozenset() as set_value:
                return {normalize_single(str(v)) for v in set_value}
        return normalize_single(str(value))

    nz = normalize_ldif

    @classmethod
    def smart_convert(
        cls,
        value: t.NormalizedValue | r[t.NormalizedValue],
        *,
        target_type: str,
        predicate: Callable[..., bool] | None = None,
        default: t.NormalizedValue = None,
    ) -> t.NormalizedValue:
        """Smart convert using FlextUtilities.build() DSL (mnemonic: sc)."""
        match value:
            case r() as result_value:
                extracted: t.NormalizedValue = (
                    result_value.value if not result_value.is_failure else default
                )
            case _:
                extracted = value
        if extracted is None:
            return default
        conv_builder = cls.conv(extracted)
        conv_result: t.NormalizedValue = None
        if target_type == "str":
            str_default = default if isinstance(default, str) else ""
            conv_result = conv_builder.to_str(default=str_default).build()
        elif target_type == "int":
            int_default = default if isinstance(default, int) else 0
            conv_result = conv_builder.to_int(default=int_default).build()
        elif target_type == "bool":
            bool_default = default if isinstance(default, bool) else False
            conv_result = conv_builder.to_bool(default=bool_default).build()
        elif target_type == "list":
            list_default: Sequence[str] = []
            match default:
                case list() | tuple() as default_seq:
                    list_default = [str(item) for item in default_seq]
                case _:
                    pass
            conv_result = conv_builder.str_list(default=list_default).build()
            if predicate and isinstance(conv_result, list):
                filtered = [item for item in conv_result if predicate(item)]
                return filtered or conv_result
        else:
            ops: Mapping[str, t.NormalizedValue] = {
                "ensure": target_type,
                "ensure_default": default,
            }
            if predicate:
                pass
            conv_result = cls.build(
                extracted,
                ops=ops,
            )
        return conv_result if conv_result is not None else default

    sc = smart_convert

    @staticmethod
    def conv(value: t.NormalizedValue) -> FlextLdifUtilitiesNormalization.ConvBuilder:
        """Create conversion builder (DSL entry point)."""
        return FlextLdifUtilitiesNormalization.ConvBuilder(value=value)

    @staticmethod
    @override
    def build(
        value: t.NormalizedValue,
        *,
        ops: Mapping[str, t.NormalizedValue] | None = None,
    ) -> t.NormalizedValue:
        """Build value using operations dict (DSL helper)."""
        if ops is None:
            return value
        return value

    @classmethod
    def as_type(
        cls,
        value: t.NormalizedValue,
        *,
        target: type | str,
        default: t.NormalizedValue | None = None,
    ) -> t.NormalizedValue:
        """Safe cast using FlextUtilities.convert() or FlextUtilities.ensure() (mnemonic: at)."""
        type_map = {
            "list": list,
            "dict": dict,
            "str": str,
            "int": int,
            "bool": bool,
            "tuple": tuple,
        }
        target_type = type_map.get(target) if isinstance(target, str) else target
        if target_type is None:
            return default
        if target_type is str:
            str_default = default if isinstance(default, str) else ""
            return cls.conv(value).to_str(default=str_default).safe().build()
        if target_type is int:
            int_default = default if isinstance(default, int) else 0
            return cls.conv(value).to_int(default=int_default).safe().build()
        if target_type is bool:
            bool_default = default if isinstance(default, bool) else False
            return cls.conv(value).to_bool(default=bool_default).safe().build()
        if target_type is list:
            list_default: Sequence[str] = []
            match default:
                case list() | tuple() as default_seq:
                    list_default = [str(item) for item in default_seq]
                case _:
                    pass
            return cls.conv(value).str_list(default=list_default).safe().build()
        ops: Mapping[str, t.NormalizedValue] = {}
        result = cls.build(
            value,
            ops=ops,
        )
        result_typed = cls.to_config_map_value(result)
        return result_typed if result_typed is not None else default

    at = as_type


__all__ = ["FlextLdifUtilitiesNormalization"]
