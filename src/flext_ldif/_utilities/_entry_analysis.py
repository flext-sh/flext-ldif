"""LDIF entry difference analysis utilities.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, MutableMapping, Sequence

from flext_cli import u

from flext_ldif import c, t


class FlextLdifEntryAnalysis:
    """Analyze differences between original and converted entries."""

    @staticmethod
    def analyze_minimal_differences(
        original: str,
        converted: str | None,
        context: str = "entry",
    ) -> t.Ldif.MutableMetadataMapping:
        """Analyze minimal differences between original and converted strings.

        Returns:
            The resulting ``t.Ldif.MutableMetadataMapping``.
        """
        mk = c.Ldif
        differences: t.Ldif.MutableMetadataMapping = {
            mk.HAS_DIFFERENCES: False,
            "context": context,
            "original": original,
            "converted": converted if converted is not None else original,
            "differences": u.normalize_to_json_value(list[str]()),
            "original_length": len(original),
            "converted_length": len(converted) if converted else len(original),
        }
        if converted is None or original == converted:
            return differences
        differences[mk.HAS_DIFFERENCES] = True
        return differences

    @staticmethod
    def _collect_original_attribute_case(
        entry_attrs: t.Ldif.MetadataInputMapping,
        normalize: Callable[[str], str],
    ) -> t.MutableStrMapping:
        """Map canonical names back to their original attribute casing.

        Returns:
            The resulting ``t.MutableStrMapping``.
        """
        original_attribute_case: t.MutableStrMapping = {}
        for attr_name in entry_attrs:
            try:
                canonical = normalize(attr_name)
                if canonical != attr_name:
                    original_attribute_case[canonical] = attr_name
            except c.EXC_BASIC_TYPE:
                continue
        return original_attribute_case

    @staticmethod
    def _original_values_list(
        attr_values: t.JsonValue | Sequence[t.JsonValue] | None,
    ) -> list[str]:
        """Flatten one attribute payload into a list of value strings.

        Returns:
            The resulting ``list[str]``.
        """
        if isinstance(attr_values, Sequence) and (
            not isinstance(attr_values, str | bytes)
        ):
            return [str(v) for v in attr_values if v is not None]
        if attr_values is not None:
            return [str(attr_values)]
        return []

    @staticmethod
    def _analyze_attribute_differences(
        entry_attrs: t.Ldif.MetadataInputMapping,
        converted_attrs: MutableMapping[str, t.MutableSequenceOf[t.Ldif.AttributeValue]],
        normalize: Callable[[str], str],
    ) -> tuple[
        MutableMapping[str, t.Ldif.MutableMetadataMapping],
        t.Ldif.MutableMetadataMapping,
    ]:
        """Build per-attribute differences and the complete original snapshot.

        Returns:
            The resulting ``tuple[MutableMapping[str, t.Ldif.MutableMetadataMapping],
                t.Ldif.MutableMetadataMapping]``.
        """
        attribute_differences: MutableMapping[str, t.Ldif.MutableMetadataMapping] = {}
        original_attributes_complete: t.Ldif.MutableMetadataMapping = {}
        for attr_name, attr_values in entry_attrs.items():
            canonical_name = normalize(attr_name)
            original_values_list = FlextLdifEntryAnalysis._original_values_list(
                attr_values,
            )
            original_attributes_complete[attr_name] = u.normalize_to_json_value(
                original_values_list,
            )
            converted_values = converted_attrs.get(canonical_name, [])
            original_str = f"{attr_name}: {', '.join(original_values_list)}"
            converted_str = (
                f"{canonical_name}: {', '.join(str(v) for v in converted_values)}"
                if converted_values
                else None
            )
            attr_diff = FlextLdifEntryAnalysis.analyze_minimal_differences(
                original=original_str,
                converted=converted_str if converted_str != original_str else None,
                context="attribute",
            )
            attribute_differences[canonical_name] = attr_diff
        return (attribute_differences, original_attributes_complete)

    @staticmethod
    def analyze_differences(
        entry_attrs: t.Ldif.MetadataInputMapping,
        converted_attrs: MutableMapping[
            str,
            t.MutableSequenceOf[t.Ldif.AttributeValue],
        ],
        original_dn: str,
        cleaned_dn: str,
        normalize_attr_fn: Callable[[str], str] | None = None,
    ) -> tuple[
        t.Ldif.MutableMetadataMapping,
        MutableMapping[str, t.Ldif.MutableMetadataMapping],
        t.Ldif.MutableMetadataMapping,
        t.MutableStrMapping,
    ]:
        """Analyze DN and attribute differences for round-trip support (DRY utility).

        Returns:
            The resulting ``tuple[t.Ldif.MutableMetadataMapping, MutableMapping[str,
                t.Ldif.MutableMetadataMapping], t.Ldif.MutableMetadataMapping,
                t.MutableStrMapping]``.
        """

        def _default_normalize(value: str) -> str:
            return value.lower()

        normalize = normalize_attr_fn or _default_normalize
        dn_differences = FlextLdifEntryAnalysis.analyze_minimal_differences(
            original=original_dn,
            converted=cleaned_dn if cleaned_dn != original_dn else None,
            context="dn",
        )
        original_attribute_case = (
            FlextLdifEntryAnalysis._collect_original_attribute_case(
                entry_attrs,
                normalize,
            )
        )
        attribute_differences, original_attributes_complete = (
            FlextLdifEntryAnalysis._analyze_attribute_differences(
                entry_attrs,
                converted_attrs,
                normalize,
            )
        )
        return (
            dn_differences,
            attribute_differences,
            original_attributes_complete,
            original_attribute_case,
        )

    @staticmethod
    def normalize_unconverted_attributes(
        value: t.JsonMapping | t.JsonValue | None,
    ) -> t.Ldif.UnconvertedAttributes:
        """Normalize metadata-carried unconverted attributes to the public LDIF shape.

        Returns:
            The resulting ``t.Ldif.UnconvertedAttributes``.
        """
        if not isinstance(value, Mapping):
            return {}
        normalized: t.Ldif.UnconvertedAttributes = {}
        for key, raw_value in value.items():
            key_str = key
            if isinstance(raw_value, str | bytes):
                normalized[key_str] = raw_value
                continue
            if isinstance(raw_value, Sequence) and not isinstance(
                raw_value,
                str | bytes,
            ):
                normalized[key_str] = [
                    str(item) for item in u.Cli.json_as_sequence(raw_value)
                ]
                continue
            normalized[key_str] = str(raw_value)
        return normalized


__all__: list[str] = ["FlextLdifEntryAnalysis"]
