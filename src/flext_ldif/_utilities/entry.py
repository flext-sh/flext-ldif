"""Extracted nested class from FlextLdifUtilities."""

from __future__ import annotations

import re
import struct
from collections.abc import Callable, Mapping, MutableMapping, MutableSequence, Sequence
from typing import Literal

from flext_core import FlextLogger, r

from flext_ldif import (
    FlextLdifModelsSettings,
    FlextLdifUtilitiesDN,
    FlextLdifUtilitiesMetadata,
    m,
    t,
)

logger = FlextLogger(__name__)


class FlextLdifUtilitiesEntry:
    """Entry transformation utilities - pure helper functions."""

    @staticmethod
    def _check_dn_pattern(entry: m.Ldif.Entry, pattern: str) -> bool:
        """Check DN pattern match."""
        dn_value = (
            entry.dn.value
            if entry.dn and getattr(entry.dn, "value", None) is not None
            else str(entry.dn)
            if entry.dn
            else ""
        )
        return bool(re.search(pattern, dn_value, re.IGNORECASE))

    @staticmethod
    def _check_objectclass_criteria(
        entry: m.Ldif.Entry,
        objectclasses: MutableSequence[str],
        mode: Literal["any", "all"],
    ) -> bool:
        """Check objectClass criteria."""
        matching_ocs: MutableSequence[str] = [
            oc
            for oc in objectclasses
            if FlextLdifUtilitiesEntry.has_objectclass(entry, oc)
        ]
        return (
            bool(matching_ocs)
            if mode == "any"
            else len(matching_ocs) == len(objectclasses)
        )

    @staticmethod
    def _check_schema_criteria(entry: m.Ldif.Entry, *, is_schema: bool) -> bool:
        """Check schema criteria."""
        return FlextLdifUtilitiesEntry.is_schema_entry(entry) == is_schema

    @staticmethod
    def _convert_attribute_values(
        values: MutableSequence[str],
        source_format: str,
        target_format: str,
    ) -> MutableSequence[str]:
        """Convert all boolean values in an attribute's value list."""
        return [
            FlextLdifUtilitiesEntry._convert_single_boolean_value(
                value,
                source_format,
                target_format,
            )
            for value in values
        ]

    @staticmethod
    def _convert_single_boolean_value(
        value: str,
        source_format: str,
        target_format: str,
    ) -> str:
        """Convert a single boolean value between formats."""
        if source_format == "0/1" and target_format == "TRUE/FALSE":
            if value not in {"1", "0"}:
                pass
            return "TRUE" if value == "1" else "FALSE"
        if source_format == "TRUE/FALSE" and target_format == "0/1":
            return "1" if value.upper() == "TRUE" else "0"
        return value

    @staticmethod
    def _stringify_attribute_value(value: str | bytes | float) -> str:
        if isinstance(value, bytes):
            return value.decode("utf-8", errors="replace")
        return str(value)

    @staticmethod
    def analyze_differences(
        entry_attrs: t.ContainerMapping,
        converted_attrs: MutableMapping[str, MutableSequence[t.Ldif.AttributeValue]],
        original_dn: str,
        cleaned_dn: str,
        normalize_attr_fn: Callable[[str], str] | None = None,
    ) -> tuple[
        t.MutableContainerMapping,
        MutableMapping[str, t.MutableContainerMapping],
        t.MutableContainerMapping,
        MutableMapping[str, str],
    ]:
        """Analyze DN and attribute differences for round-trip support (DRY utility)."""

        def _default_normalize(value: str) -> str:
            return value.lower()

        normalize = normalize_attr_fn or _default_normalize
        dn_differences = FlextLdifUtilitiesMetadata.analyze_minimal_differences(
            original=original_dn,
            converted=cleaned_dn if cleaned_dn != original_dn else None,
            context="dn",
        )

        def extract_case_mapping(attr_name: str) -> tuple[str, str] | None:
            """Extract case mapping if different."""
            attr_str = str(attr_name)
            canonical = normalize(attr_str)
            return (canonical, attr_str) if canonical != attr_str else None

        original_attribute_case: MutableMapping[str, str] = {}
        for attr_name in entry_attrs:
            try:
                result = extract_case_mapping(attr_name)
                if result is not None:
                    key, value = result
                    original_attribute_case[key] = value
            except (ValueError, TypeError, AttributeError):
                continue
        attribute_differences: MutableMapping[str, t.MutableContainerMapping] = {}
        original_attributes_complete: t.MutableContainerMapping = {}
        for attr_name, attr_values in entry_attrs.items():
            original_attr_name = str(attr_name)
            canonical_name = normalize(original_attr_name)
            original_values_list: MutableSequence[str] = []
            if isinstance(attr_values, Sequence) and (
                not isinstance(attr_values, str | bytes)
            ):
                original_values_list = [str(v) for v in attr_values if v is not None]
            elif attr_values is not None:
                original_values_list = [str(attr_values)]
            typed_list: t.NormalizedValue = list(original_values_list)
            original_attributes_complete[original_attr_name] = typed_list
            converted_values = converted_attrs.get(canonical_name, [])
            original_str = f"{original_attr_name}: {', '.join(original_values_list)}"
            converted_str = (
                f"{canonical_name}: {', '.join(str(v) for v in converted_values)}"
                if converted_values
                else None
            )
            attr_diff = FlextLdifUtilitiesMetadata.analyze_minimal_differences(
                original=original_str,
                converted=converted_str if converted_str != original_str else None,
                context="attribute",
            )
            attribute_differences[canonical_name] = attr_diff
        return (
            dn_differences,
            attribute_differences,
            original_attributes_complete,
            original_attribute_case,
        )

    @staticmethod
    def convert_boolean_attributes(
        attributes: Mapping[
            str, MutableSequence[str] | MutableSequence[bytes] | str | bytes
        ],
        boolean_attr_names: set[str],
        *,
        source_format: str = "0/1",
        target_format: str = "TRUE/FALSE",
    ) -> MutableMapping[str, MutableSequence[str]]:
        """Convert boolean attribute values between formats."""
        if not attributes or not boolean_attr_names:
            if not attributes:
                return {}
            normalized_result: MutableMapping[str, MutableSequence[str]] = {}
            for attr_name in attributes:
                raw_values = attributes[attr_name]
                if isinstance(raw_values, str | bytes):
                    normalized_result[attr_name] = [
                        FlextLdifUtilitiesEntry._stringify_attribute_value(raw_values),
                    ]
                else:
                    normalized_result[attr_name] = [
                        FlextLdifUtilitiesEntry._stringify_attribute_value(v)
                        for v in raw_values
                    ]
            return normalized_result
        result: MutableMapping[str, MutableSequence[str]] = {}
        for attr_name in attributes:
            attr_raw_values = attributes[attr_name]
            str_values: MutableSequence[str]
            if isinstance(attr_raw_values, str | bytes):
                str_values = [
                    FlextLdifUtilitiesEntry._stringify_attribute_value(attr_raw_values),
                ]
            else:
                str_values = [
                    FlextLdifUtilitiesEntry._stringify_attribute_value(v)
                    for v in attr_raw_values
                ]
            if attr_name.lower() in boolean_attr_names:
                result[attr_name] = FlextLdifUtilitiesEntry._convert_attribute_values(
                    str_values,
                    source_format,
                    target_format,
                )
            else:
                result[attr_name] = str_values
        return result

    @staticmethod
    def filter_batch(
        entries: MutableSequence[m.Ldif.Entry],
        config: FlextLdifModelsSettings.FlextLdifUtilitiesFiltersConfig | None = None,
        **kwargs: str | float | bool | None,
    ) -> r[MutableSequence[m.Ldif.Entry]]:
        """Filter entries based on criteria."""
        if config is None:
            effective_is_schema = kwargs.get("is_schema")
            exclude_schema = kwargs.get("exclude_schema", False)
            if exclude_schema and effective_is_schema is None:
                effective_is_schema = False
            kwargs["is_schema"] = effective_is_schema
            config = (
                FlextLdifModelsSettings.FlextLdifUtilitiesFiltersConfig.model_validate(
                    kwargs,
                )
            )
        filtered: MutableSequence[m.Ldif.Entry] = [
            entry
            for entry in entries
            if FlextLdifUtilitiesEntry.matches_criteria(
                entry,
                config=FlextLdifModelsSettings.EntryCriteriaConfig(
                    objectclasses=config.objectclasses,
                    objectclass_mode=config.objectclass_mode,
                    required_attrs=config.required_attrs,
                    dn_pattern=config.dn_pattern,
                    is_schema=config.is_schema if not config.exclude_schema else False,
                ),
            )
        ]
        return r[MutableSequence[m.Ldif.Entry]].ok(filtered)

    @staticmethod
    def has_all_attributes(
        entry: m.Ldif.Entry, attributes: MutableSequence[str]
    ) -> bool:
        """Check if entry has ALL specified attributes."""
        if not attributes:
            return True
        if not entry.attributes:
            return False
        entry_attrs_lower = {k.lower() for k in entry.attributes.attributes}
        return all(attr.lower() in entry_attrs_lower for attr in attributes)

    @staticmethod
    def has_any_attributes(
        entry: m.Ldif.Entry, attributes: MutableSequence[str]
    ) -> bool:
        """Check if entry has ANY of the specified attributes."""
        if not attributes:
            return False
        if not entry.attributes:
            return False
        entry_attrs_lower = {k.lower() for k in entry.attributes.attributes}
        return any(attr.lower() in entry_attrs_lower for attr in attributes)

    @staticmethod
    def has_objectclass(
        entry: m.Ldif.Entry,
        objectclasses: str | tuple[str, ...],
    ) -> bool:
        """Check if entry has any of the specified objectClasses."""
        if not entry.attributes:
            return False
        objectclass_candidates: tuple[str, ...] = (
            (objectclasses,) if isinstance(objectclasses, str) else objectclasses
        )
        entry_ocs = entry.attributes.get("objectClass", [])
        entry_ocs_lower = {oc.lower() for oc in entry_ocs}
        return any(oc.lower() in entry_ocs_lower for oc in objectclass_candidates)

    @staticmethod
    def is_schema_entry(entry: m.Ldif.Entry, *, strict: bool = True) -> bool:
        """Check if entry is a REAL schema entry with schema definitions."""
        if entry.attributes is None:
            return False
        attrs_lower = {k.lower() for k in entry.attributes.attributes}
        schema_field_names = ["attributetypes", "objectclasses"]
        has_schema_attrs = any(sf.lower() in attrs_lower for sf in schema_field_names)
        dn_lower = entry.dn.value.lower() if entry.dn else ""
        schema_dn_patterns = ["cn=subschemasubentry", "cn=subschema", "cn=schema"]
        has_schema_dn = any(pattern in dn_lower for pattern in schema_dn_patterns)
        object_classes = entry.attributes.get("objectClass", [])
        has_schema_objectclass = any(
            oc.lower() in {"subschema", "subentry"} for oc in object_classes
        )
        if strict:
            if not has_schema_attrs:
                return False
            return has_schema_dn
        return has_schema_dn or has_schema_objectclass or has_schema_attrs

    @staticmethod
    def matches_criteria(
        entry: m.Ldif.Entry,
        config: FlextLdifModelsSettings.EntryCriteriaConfig | None = None,
        **kwargs: str | float | bool | None,
    ) -> bool:
        """Check multiple entry criteria in one call."""
        if config is None:
            config = FlextLdifModelsSettings.EntryCriteriaConfig.model_validate(kwargs)
        checks: MutableSequence[bool] = []
        if config.is_schema is not None:
            checks.append(
                FlextLdifUtilitiesEntry._check_schema_criteria(
                    entry,
                    is_schema=config.is_schema,
                ),
            )
        if config.objectclasses:
            checks.append(
                FlextLdifUtilitiesEntry._check_objectclass_criteria(
                    entry,
                    config.objectclasses,
                    config.objectclass_mode,
                ),
            )
        if config.required_attrs:
            checks.append(
                FlextLdifUtilitiesEntry.has_all_attributes(
                    entry,
                    list(config.required_attrs),
                ),
            )
        if config.any_attrs:
            checks.append(
                FlextLdifUtilitiesEntry.has_any_attributes(
                    entry,
                    list(config.any_attrs),
                ),
            )
        if config.dn_pattern:
            checks.append(
                FlextLdifUtilitiesEntry._check_dn_pattern(entry, config.dn_pattern),
            )
        return all(checks)

    @staticmethod
    def matches_entry_server_patterns(
        entry_dn: str,
        attributes: Mapping[str, Sequence[str]],
        config: FlextLdifModelsSettings.ServerPatternsConfig,
    ) -> bool:
        """Check if entry matches server-specific patterns."""
        if not entry_dn or not attributes:
            return False
        attrs = (
            dict(attributes)
            if not issubclass(attributes.__class__, dict)
            else attributes
        )
        attr_names_lower = {k.lower() for k in attrs}
        if config.dn_patterns and any(
            all(pattern in entry_dn for pattern in pattern_set)
            for pattern_set in config.dn_patterns
        ):
            return True
        if config.attr_prefixes and any(
            attr.startswith(prefix) for attr in attrs for prefix in config.attr_prefixes
        ):
            return True
        if config.attr_names and attr_names_lower & set(config.attr_names):
            return True
        if config.keyword_patterns:
            return any(
                keyword in attr
                for attr in attr_names_lower
                for keyword in config.keyword_patterns
            )
        return False

    @staticmethod
    def normalize_attribute_names(
        attributes: MutableMapping[str, MutableSequence[t.Ldif.AttributeValue]],
        case_map: MutableMapping[str, str],
    ) -> MutableMapping[str, MutableSequence[t.Ldif.AttributeValue]]:
        """Normalize attribute names using case mapping."""
        if not attributes or not case_map:
            return dict(attributes)

        def get_normalized_name(attr_name: str) -> str:
            """Get normalized attribute name."""
            return case_map.get(attr_name.lower(), attr_name)

        result: MutableMapping[str, MutableSequence[t.Ldif.AttributeValue]] = {}
        for attr_name, values in attributes.items():
            normalized_name = get_normalized_name(attr_name)
            result[normalized_name] = values
        return result

    @staticmethod
    def normalize_attributes_batch(
        attributes: MutableMapping[str, MutableSequence[t.Ldif.AttributeValue]],
        *,
        config: FlextLdifModelsSettings.AttributeNormalizeConfig | None = None,
        **kwargs: str | float | bool | None,
    ) -> MutableMapping[str, MutableSequence[t.Ldif.AttributeValue]]:
        """Batch normalize attributes from server format to RFC format."""
        if config is None:
            config = FlextLdifModelsSettings.AttributeNormalizeConfig.model_validate(
                kwargs,
            )
        result: MutableMapping[str, MutableSequence[str | bytes]] = {}
        operational_lower: set[str] = (
            {a.lower() for a in config.operational_attrs}
            if config.operational_attrs
            else set()
        )
        for attr_name, values in attributes.items():
            if config.strip_operational and attr_name.lower() in operational_lower:
                continue
            output_name = attr_name.lower()
            if config.case_mappings:
                output_name = config.case_mappings.get(attr_name, output_name)
            if config.attr_name_mappings:
                output_name = config.attr_name_mappings.get(attr_name, output_name)

            def normalize_value(value: t.Ldif.AttributeValue) -> str:
                """Normalize single value."""
                normalized_value = FlextLdifUtilitiesEntry._stringify_attribute_value(
                    value,
                )
                if (
                    config.boolean_mappings
                    and normalized_value in config.boolean_mappings
                ):
                    return config.boolean_mappings[normalized_value]
                return normalized_value

            output_values: MutableSequence[str | bytes] = [
                normalize_value(value) for value in values
            ]
            result[output_name] = output_values
        return result

    @staticmethod
    def remove_attributes(
        entry: m.Ldif.Entry, attributes: MutableSequence[str]
    ) -> m.Ldif.Entry:
        """Remove specified attributes from entry."""
        if not attributes or entry.attributes is None or entry.dn is None:
            return entry
        attrs_to_remove = {attr.lower() for attr in attributes}
        filtered: MutableMapping[str, MutableSequence[str]] = {
            k: v
            for k, v in entry.attributes.attributes.items()
            if k.lower() not in attrs_to_remove
        }
        return m.Ldif.Entry.create(
            dn=entry.dn,
            attributes=m.Ldif.Attributes.model_validate({"attributes": filtered}),
        ).unwrap_or(entry)

    @staticmethod
    def transform_batch(
        entries: MutableSequence[m.Ldif.Entry],
        config: FlextLdifModelsSettings.EntryTransformConfig | None = None,
        **kwargs: str | float | bool | None,
    ) -> r[MutableSequence[m.Ldif.Entry]]:
        """Transform multiple entries with common operations."""
        if config is None:
            config = FlextLdifModelsSettings.EntryTransformConfig.model_validate(kwargs)

        def transform_entry(entry: m.Ldif.Entry) -> m.Ldif.Entry:
            """Transform single entry with all operations."""
            current = entry
            if config.normalize_dns and current.dn:
                dn_value = (
                    current.dn.value
                    if getattr(current.dn, "value", None) is not None
                    else str(current.dn)
                )
                norm_result = FlextLdifUtilitiesDN.norm(dn_value)
                if norm_result.is_success:
                    current = current.model_copy(
                        update={"dn": m.Ldif.DN(value=norm_result.value)},
                    )
            if config.normalize_attrs and current.attributes:
                attrs = current.attributes.attributes
                new_attrs = (
                    {k.lower(): v for k, v in attrs.items()}
                    if config.attr_case == "lower"
                    else {k.upper(): v for k, v in attrs.items()}
                    if config.attr_case == "upper"
                    else attrs
                )
                current = current.model_copy(
                    update={
                        "attributes": m.Ldif.Attributes.model_validate({
                            "attributes": {**new_attrs}
                        })
                    },
                )
            if config.convert_booleans and current.attributes:
                source_format, target_format = config.convert_booleans
                boolean_attrs = {
                    "userpassword",
                    "pwdaccountlocked",
                    "pwdlocked",
                    "accountlocked",
                    "passwordexpired",
                    "passwordneverexpires",
                }
                converted = FlextLdifUtilitiesEntry.convert_boolean_attributes(
                    current.attributes.attributes,
                    boolean_attrs,
                    source_format=source_format,
                    target_format=target_format,
                )
                current = current.model_copy(
                    update={
                        "attributes": m.Ldif.Attributes.model_validate({
                            "attributes": {**converted}
                        })
                    },
                )
            if config.remove_attrs:
                current = FlextLdifUtilitiesEntry.remove_attributes(
                    current,
                    list(config.remove_attrs),
                )
            return current

        transformed_list: MutableSequence[m.Ldif.Entry] = []
        errors: MutableSequence[tuple[int, str]] = []
        for i, entry in enumerate(entries):
            try:
                result = transform_entry(entry)
                transformed_list.append(result)
            except (
                ValueError,
                KeyError,
                AttributeError,
                UnicodeDecodeError,
                struct.error,
            ) as exc:
                if config.fail_fast:
                    return r[MutableSequence[m.Ldif.Entry]].fail(
                        f"Transform failed at entry {i}: {exc}",
                    )
                errors.append((i, f"Transform failed at entry {i}: {exc}"))
        if errors and config.fail_fast:
            error_msg = errors[0][1]
            return r[MutableSequence[m.Ldif.Entry]].fail(error_msg)
        return r[MutableSequence[m.Ldif.Entry]].ok(transformed_list)


__all__ = ["FlextLdifUtilitiesEntry"]
