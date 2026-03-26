"""Normalization/conversion utilities for FLEXT-LDIF."""

from __future__ import annotations

import contextlib
from collections.abc import MutableSequence
from typing import Self

from flext_core import FlextUtilities

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
        mapping: t.MutableContainerMapping,
    ) -> t.MutableContainerMapping:
        """Normalize a mapping of objects to a standard dict form."""
        normalized: t.MutableContainerMapping = {}
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
                list_default: MutableSequence[str] = []
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

        def str_list(self, default: MutableSequence[str] | None = None) -> Self:
            """Convert to string list using parent Conversion utilities."""
            self._default = default if default is not None else []
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

    @staticmethod
    def conv(value: t.NormalizedValue) -> FlextLdifUtilitiesNormalization.ConvBuilder:
        """Create conversion builder (DSL entry point)."""
        return FlextLdifUtilitiesNormalization.ConvBuilder(value=value)

    @staticmethod
    def build(
        value: t.NormalizedValue,
        *,
        ops: t.MutableContainerMapping | None = None,
    ) -> t.NormalizedValue:
        """Build value using operations dict (DSL helper)."""
        if ops is None:
            return value
        return value


__all__ = ["FlextLdifUtilitiesNormalization"]
