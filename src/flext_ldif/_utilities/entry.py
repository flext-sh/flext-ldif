"""Extracted nested class from FlextLdifUtilities."""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping, Sequence
from typing import Literal

from flext_core import FlextLogger, FlextResult, FlextTypes, r

from flext_ldif._models.settings import FlextLdifModelsSettings
from flext_ldif._utilities.dn import FlextLdifUtilitiesDN
from flext_ldif._utilities.metadata import FlextLdifUtilitiesMetadata
from flext_ldif.models import m
from flext_ldif.typings import t

logger = FlextLogger(__name__)


class FlextLdifUtilitiesEntry:
    """Entry transformation utilities - pure helper functions."""

    @staticmethod
    def _convert_single_boolean_value(
        value: str,
        source_format: str,
        target_format: str,
    ) -> str:
        """Convert a single boolean value between formats."""
        if source_format == "0/1" and target_format == "TRUE/FALSE":
            return "TRUE" if value == "1" else "FALSE"
        if source_format == "TRUE/FALSE" and target_format == "0/1":
            return "1" if value.upper() == "TRUE" else "0"
        return value

    @staticmethod
    def _convert_attribute_values(
        values: list[str],
        source_format: str,
        target_format: str,
    ) -> list[str]:
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
    def convert_boolean_attributes(
        attributes: Mapping[str, list[str] | list[bytes] | bytes | str],
        boolean_attr_names: set[str],
        *,
        source_format: str = "0/1",
        target_format: str = "TRUE/FALSE",
    ) -> t.Ldif.NormalizedAttributesDict:
        """Convert boolean attribute values between formats."""
        if not attributes or not boolean_attr_names:
            if not attributes:
                return {}
            normalized_result: t.Ldif.NormalizedAttributesDict = {}
            for attr_name in attributes:
                raw_values: list[str] | list[bytes] | bytes | str = attributes[
                    attr_name
                ]
                if isinstance(raw_values, (list, tuple)):
                    normalized_result[attr_name] = [
                        v.decode("utf-8", errors="replace")
                        if isinstance(v, bytes)
                        else str(v)
                        for v in raw_values
                    ]
                elif isinstance(raw_values, bytes):
                    normalized_result[attr_name] = [
                        raw_values.decode("utf-8", errors="replace"),
                    ]
                else:
                    normalized_result[attr_name] = [str(raw_values)]
            return normalized_result

        result: dict[str, list[str]] = {}

        for attr_name in attributes:
            attr_raw_values: list[str] | list[bytes] | bytes | str = attributes[
                attr_name
            ]
            str_values: list[str]
            if isinstance(attr_raw_values, (list, tuple)):
                str_values = [
                    v.decode("utf-8", errors="replace")
                    if isinstance(v, bytes)
                    else str(v)
                    for v in attr_raw_values
                ]
            elif isinstance(attr_raw_values, bytes):
                str_values = [attr_raw_values.decode("utf-8", errors="replace")]
            else:
                str_values = [str(attr_raw_values)]

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
    def normalize_attribute_names(
        attributes: t.Ldif.AttributesDict,
        case_map: dict[str, str],
    ) -> t.Ldif.AttributesDict:
        """Normalize attribute names using case mapping."""
        if not attributes or not case_map:
            return attributes

        def get_normalized_name(attr_name: str) -> str:
            """Get normalized attribute name."""
            return case_map.get(attr_name.lower(), attr_name)

        result: t.Ldif.AttributesDict = {}
        for attr_name, values in attributes.items():
            normalized_name = get_normalized_name(attr_name)
            result[normalized_name] = values
        return result

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
    def has_objectclass(
        entry: m.Ldif.Entry,
        objectclasses: str | tuple[str, ...],
    ) -> bool:
        """Check if entry has any of the specified objectClasses."""
        if not entry.attributes:
            return False

        if isinstance(objectclasses, str):
            objectclasses = (objectclasses,)

        entry_ocs = entry.attributes.get("objectClass", [])
        entry_ocs_lower = {oc.lower() for oc in entry_ocs}

        return any(oc.lower() in entry_ocs_lower for oc in objectclasses)

    @staticmethod
    def has_all_attributes(
        entry: m.Ldif.Entry,
        attributes: list[str],
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
        entry: m.Ldif.Entry,
        attributes: list[str],
    ) -> bool:
        """Check if entry has ANY of the specified attributes."""
        if not attributes:
            return False

        if not entry.attributes:
            return False

        entry_attrs_lower = {k.lower() for k in entry.attributes.attributes}
        return any(attr.lower() in entry_attrs_lower for attr in attributes)

    @staticmethod
    def remove_attributes(
        entry: m.Ldif.Entry,
        attributes: list[str],
    ) -> m.Ldif.Entry:
        """Remove specified attributes from entry."""
        if not attributes or entry.attributes is None or entry.dn is None:
            return entry

        attrs_to_remove = {attr.lower() for attr in attributes}
        filtered: dict[str, list[str]] = {
            k: v
            for k, v in entry.attributes.attributes.items()
            if k.lower() not in attrs_to_remove
        }

        return m.Ldif.Entry.create(
            dn=entry.dn,
            attributes=m.Ldif.Attributes(attributes=filtered),
        ).unwrap_or(entry)

    @staticmethod
    def analyze_differences(
        entry_attrs: Mapping[str, FlextTypes.GeneralValueType],
        converted_attrs: t.Ldif.AttributesDict,
        original_dn: str,
        cleaned_dn: str,
        normalize_attr_fn: Callable[[str], str] | None = None,
    ) -> tuple[
        dict[str, t.MetadataAttributeValue],
        dict[str, dict[str, t.MetadataAttributeValue]],
        dict[str, t.MetadataAttributeValue],
        dict[str, str],
    ]:
        """Analyze DN and attribute differences for round-trip support (DRY utility)."""
        normalize = normalize_attr_fn or (lambda x: x.lower())

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

        original_attribute_case: dict[str, str] = {}
        for attr_name in entry_attrs:
            try:
                result = extract_case_mapping(attr_name)
                if result is not None:
                    key, value = result
                    original_attribute_case[key] = value
            except (ValueError, TypeError, AttributeError):
                continue

        attribute_differences: dict[
            str,
            dict[str, t.MetadataAttributeValue],
        ] = {}
        original_attributes_complete: dict[str, t.MetadataAttributeValue] = {}

        for attr_name, attr_values in entry_attrs.items():
            original_attr_name = str(attr_name)
            canonical_name = normalize(original_attr_name)

            original_values_list: list[str] = []
            if isinstance(attr_values, (list, tuple)):
                original_values_list = [str(v) for v in attr_values if v is not None]
            elif attr_values is not None:
                original_values_list = [str(attr_values)]
            typed_list: t.MetadataAttributeValue = list(original_values_list)
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
    def matches_server_patterns(
        entry_dn: str,
        attributes: Mapping[str, FlextTypes.GeneralValueType],
        config: FlextLdifModelsSettings.ServerPatternsConfig,
    ) -> bool:
        """Check if entry matches server-specific patterns."""
        if not entry_dn or not attributes:
            return False

        attrs = dict(attributes) if not isinstance(attributes, dict) else attributes
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

        if config.attr_names and (attr_names_lower & set(config.attr_names)):
            return True

        if config.keyword_patterns:
            return any(
                keyword in attr
                for attr in attr_names_lower
                for keyword in config.keyword_patterns
            )

        return False

    @staticmethod
    def normalize_attributes_batch(
        attributes: t.Ldif.AttributesDict,
        *,
        config: FlextLdifModelsSettings.AttributeNormalizeConfig | None = None,
        **kwargs: object,
    ) -> t.Ldif.AttributesDict:
        """Batch normalize attributes from server format to RFC format."""
        if config is None:
            config = FlextLdifModelsSettings.AttributeNormalizeConfig.model_validate(
                kwargs,
            )

        result: dict[str, list[str | bytes]] = {}

        operational_lower = (
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

            def normalize_value(value: str) -> str:
                """Normalize single value."""
                if config.boolean_mappings and value in config.boolean_mappings:
                    return config.boolean_mappings[value]
                return value

            output_values: list[str | bytes] = []
            for value in values:
                if isinstance(value, str):
                    output_values.append(normalize_value(value))
                else:
                    output_values.append(str(value))

            result[output_name] = output_values

        return result

    @staticmethod
    def _check_schema_criteria(entry: m.Ldif.Entry, *, is_schema: bool) -> bool:
        """Check schema criteria."""
        return FlextLdifUtilitiesEntry.is_schema_entry(entry) == is_schema

    @staticmethod
    def _check_objectclass_criteria(
        entry: m.Ldif.Entry,
        objectclasses: Sequence[str],
        mode: Literal["any", "all"],
    ) -> bool:
        """Check objectClass criteria."""
        matching_ocs: list[str] = [
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
    def _check_dn_pattern(entry: m.Ldif.Entry, pattern: str) -> bool:
        """Check DN pattern match."""
        dn_value = (
            entry.dn.value
            if entry.dn and hasattr(entry.dn, "value")
            else str(entry.dn)
            if entry.dn
            else ""
        )
        return bool(re.search(pattern, dn_value, re.IGNORECASE))

    @staticmethod
    def matches_criteria(
        entry: m.Ldif.Entry,
        config: FlextLdifModelsSettings.EntryCriteriaConfig | None = None,
        **kwargs: object,
    ) -> bool:
        """Check multiple entry criteria in one call."""
        if config is None:
            config = FlextLdifModelsSettings.EntryCriteriaConfig.model_validate(kwargs)

        checks: list[bool] = []

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
    def transform_batch(
        entries: Sequence[m.Ldif.Entry],
        config: FlextLdifModelsSettings.EntryTransformConfig | None = None,
        **kwargs: object,
    ) -> FlextResult[list[m.Ldif.Entry]]:
        """Transform multiple entries with common operations."""
        if config is None:
            config = FlextLdifModelsSettings.EntryTransformConfig.model_validate(kwargs)

        def transform_entry(
            entry: m.Ldif.Entry,
        ) -> m.Ldif.Entry:
            """Transform single entry with all operations."""
            current = entry
            if config.normalize_dns and current.dn:
                dn_value = (
                    current.dn.value
                    if hasattr(current.dn, "value")
                    else str(current.dn)
                )
                norm_result = FlextLdifUtilitiesDN.norm(dn_value)
                if norm_result.is_success:
                    dn_update: dict[str, t.GeneralValueType] = {
                        "dn": m.Ldif.DN(value=norm_result.value),
                    }
                    current = current.model_copy(update=dn_update)
            if config.normalize_attrs and current.attributes:
                attrs = current.attributes.attributes
                new_attrs = (
                    {k.lower(): v for k, v in attrs.items()}
                    if config.attr_case == "lower"
                    else {k.upper(): v for k, v in attrs.items()}
                    if config.attr_case == "upper"
                    else attrs
                )
                attrs_update: dict[str, t.GeneralValueType] = {
                    "attributes": m.Ldif.Attributes(attributes=new_attrs),
                }
                current = current.model_copy(update=attrs_update)
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
                converted_attrs_update: dict[str, t.GeneralValueType] = {
                    "attributes": m.Ldif.Attributes(attributes=converted),
                }
                current = current.model_copy(update=converted_attrs_update)
            if config.remove_attrs:
                current = FlextLdifUtilitiesEntry.remove_attributes(
                    current,
                    list(config.remove_attrs),
                )
            return current

        transformed_list: list[m.Ldif.Entry] = []
        errors: list[tuple[int, str]] = []
        for i, entry in enumerate(entries):
            try:
                result = transform_entry(entry)
                if isinstance(result, m.Ldif.Entry):
                    transformed_list.append(result)
            except Exception as exc:
                if config.fail_fast:
                    return r[list[m.Ldif.Entry]].fail(
                        f"Transform failed at entry {i}: {exc}",
                    )
                errors.append((i, f"Transform failed at entry {i}: {exc}"))

        if errors and config.fail_fast:
            error_msg = errors[0][1]
            return r[list[m.Ldif.Entry]].fail(error_msg)

        return r[list[m.Ldif.Entry]].ok(transformed_list)

    @staticmethod
    def filter_batch(
        entries: Sequence[m.Ldif.Entry],
        config: FlextLdifModelsSettings.EntryFilterConfig | None = None,
        **kwargs: object,
    ) -> FlextResult[list[m.Ldif.Entry]]:
        """Filter entries based on criteria."""
        if config is None:
            effective_is_schema = kwargs.get("is_schema")
            exclude_schema = kwargs.get("exclude_schema", False)
            if exclude_schema and effective_is_schema is None:
                effective_is_schema = False
            kwargs["is_schema"] = effective_is_schema
            config = FlextLdifModelsSettings.EntryFilterConfig.model_validate(kwargs)

        filtered: list[m.Ldif.Entry] = [
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

        return r[list[m.Ldif.Entry]].ok(filtered)


__all__ = [
    "FlextLdifUtilitiesEntry",
]
