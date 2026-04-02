"""Extracted nested class from FlextLdifUtilities."""

from __future__ import annotations

import re
import struct
from collections.abc import Callable, Mapping, MutableMapping, MutableSequence, Sequence

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
            str,
            MutableSequence[str] | MutableSequence[bytes] | str | bytes,
        ],
        boolean_attr_names: set[str],
        *,
        source_format: str = "0/1",
        target_format: str = "TRUE/FALSE",
    ) -> MutableMapping[str, MutableSequence[str]]:
        """Convert boolean attribute values between formats."""

        def _stringify(value: str | bytes | float) -> str:
            if isinstance(value, bytes):
                return value.decode("utf-8", errors="replace")
            return str(value)

        def _convert_bool(value: str) -> str:
            if source_format == "0/1" and target_format == "TRUE/FALSE":
                return "TRUE" if value == "1" else "FALSE"
            if source_format == "TRUE/FALSE" and target_format == "0/1":
                return "1" if value.upper() == "TRUE" else "0"
            return value

        if not attributes or not boolean_attr_names:
            if not attributes:
                return {}
            normalized_result: MutableMapping[str, MutableSequence[str]] = {}
            for attr_name in attributes:
                raw_values = attributes[attr_name]
                if isinstance(raw_values, str | bytes):
                    normalized_result[attr_name] = [_stringify(raw_values)]
                else:
                    normalized_result[attr_name] = [_stringify(v) for v in raw_values]
            return normalized_result
        result: MutableMapping[str, MutableSequence[str]] = {}
        for attr_name in attributes:
            attr_raw_values = attributes[attr_name]
            str_values: MutableSequence[str]
            if isinstance(attr_raw_values, str | bytes):
                str_values = [_stringify(attr_raw_values)]
            else:
                str_values = [_stringify(v) for v in attr_raw_values]
            if attr_name.lower() in boolean_attr_names:
                result[attr_name] = [_convert_bool(v) for v in str_values]
            else:
                result[attr_name] = str_values
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
    def matches_criteria(
        entry: m.Ldif.Entry,
        config: FlextLdifModelsSettings.EntryCriteriaConfig | None = None,
        **kwargs: str | float | bool | None,
    ) -> bool:
        """Check multiple entry criteria in one call."""
        if config is None:
            config = FlextLdifModelsSettings.EntryCriteriaConfig.model_validate(kwargs)
        assert config is not None  # noqa: S101
        checks: MutableSequence[bool] = []
        if config.is_schema is not None:
            checks.append(
                FlextLdifUtilitiesEntry.is_schema_entry(entry) == config.is_schema,
            )
        if config.objectclasses:
            entry_ocs = (
                entry.attributes.get("objectClass", [])
                if entry.attributes
                else list[str]()
            )
            entry_ocs_lower = {oc.lower() for oc in entry_ocs}
            matching = [
                oc for oc in config.objectclasses if oc.lower() in entry_ocs_lower
            ]
            checks.append(
                bool(matching)
                if config.objectclass_mode == "any"
                else len(matching) == len(config.objectclasses),
            )
        if config.required_attrs:
            if not entry.attributes:
                checks.append(False)
            else:
                entry_attrs_lower = {k.lower() for k in entry.attributes.attributes}
                checks.append(
                    all(a.lower() in entry_attrs_lower for a in config.required_attrs),
                )
        if config.any_attrs:
            if not entry.attributes:
                checks.append(False)
            else:
                entry_attrs_lower = {k.lower() for k in entry.attributes.attributes}
                checks.append(
                    any(a.lower() in entry_attrs_lower for a in config.any_attrs),
                )
        if config.dn_pattern:
            dn_value = (
                entry.dn.value
                if entry.dn and getattr(entry.dn, "value", None) is not None
                else str(entry.dn)
                if entry.dn
                else ""
            )
            checks.append(bool(re.search(config.dn_pattern, dn_value, re.IGNORECASE)))
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
    def remove_attributes(
        entry: m.Ldif.Entry,
        attributes: MutableSequence[str],
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
        assert config is not None  # noqa: S101

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
                            "attributes": {**new_attrs},
                        }),
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
                            "attributes": {**converted},
                        }),
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
