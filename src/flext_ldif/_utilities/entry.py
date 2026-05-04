"""Extracted nested class from FlextLdifUtilities."""

from __future__ import annotations

from collections.abc import (
    Callable,
    Mapping,
    MutableMapping,
    Sequence,
)

from flext_cli import u
from flext_ldif import FlextLdifModelsSettings, c, p, t


class FlextLdifUtilitiesEntry:
    """Entry transformation utilities - pure helper functions."""

    logger = u.fetch_logger(__name__)

    # --- Entry getters/checkers (take entry as first param) ---

    @staticmethod
    def get_attribute_values(
        entry: p.Ldif.Entry,
        attribute_name: str,
    ) -> t.MutableSequenceOf[str]:
        """Get all values for a specific attribute (case-insensitive).

        Args:
            entry: LDIF entry to query
            attribute_name: Name of the attribute to retrieve

        Returns:
            List of attribute values, empty list if attribute doesn't exist

        """
        if entry.attributes is None:
            return []
        attrs_dict = entry.attributes.attributes
        if not attrs_dict:
            return []
        attr_name_lower = attribute_name.lower()
        for stored_name, attr_values in attrs_dict.items():
            if stored_name.lower() == attr_name_lower:
                return attr_values
        return []

    @staticmethod
    def get_dn_components(entry: p.Ldif.Entry) -> t.MutableSequenceOf[str]:
        """Get DN components (RDN parts) from the entry's DN.

        Returns:
            List of DN components (e.g., ["cn=admin", "dc=example", "dc=com"])

        """
        if entry.dn is None:
            return []
        return [comp.strip() for comp in entry.dn.value.split(",") if comp.strip()]

    @staticmethod
    def get_objectclass_names(entry: p.Ldif.Entry) -> t.MutableSequenceOf[str]:
        """Get list of objectClass attribute values from entry."""
        return FlextLdifUtilitiesEntry.get_attribute_values(
            entry,
            c.Ldif.DictKeys.OBJECTCLASS,
        )

    @staticmethod
    def has_attribute(entry: p.Ldif.Entry, attribute_name: str) -> bool:
        """Check if entry has a specific attribute (case-insensitive).

        Args:
            entry: LDIF entry to check
            attribute_name: Name of the attribute to check

        Returns:
            True if attribute exists with at least one value, False otherwise

        """
        return bool(FlextLdifUtilitiesEntry.get_attribute_values(entry, attribute_name))

    @staticmethod
    def has_object_class(entry: p.Ldif.Entry, object_class: str) -> bool:
        """Check if entry has specified object class.

        Args:
            entry: LDIF entry to check
            object_class: Name of the object class to check

        Returns:
            True if entry has the object class, False otherwise

        """
        return object_class in FlextLdifUtilitiesEntry.get_attribute_values(
            entry,
            c.Ldif.DictKeys.OBJECTCLASS,
        )

    @staticmethod
    def remap_oid_rfc_attributes(
        attributes: t.MutableStrSequenceMapping,
        *,
        attribute_mapping: t.StrMapping,
        boolean_value_mapping: t.StrMapping,
    ) -> t.MutableStrSequenceMapping:
        """Remap attribute names and boolean values for OID/RFC compatibility."""
        remapped: t.MutableStrSequenceMapping = {}
        for attr_name, values in attributes.items():
            normalized_name = attr_name.lower()
            normalized_values: t.MutableSequenceOf[str] = list(values)
            converted_values = (
                [boolean_value_mapping.get(value, value) for value in normalized_values]
                if normalized_name in c.Ldif.OID_BOOLEAN_ATTRIBUTES
                else normalized_values
            )
            mapped_name = attribute_mapping.get(normalized_name, normalized_name)
            remapped[mapped_name] = converted_values
        return remapped

    @staticmethod
    def transform_entry_attributes_between_oid_rfc(
        entry: p.Ldif.Entry,
        source_type_norm: str,
        target_type_norm: str,
    ) -> t.MutableStrSequenceMapping | None:
        """Compute transformed attribute map between OID and RFC formats."""
        attributes_model = entry.attributes
        if attributes_model is None or not attributes_model.attributes:
            return None
        current_attrs = dict(attributes_model.attributes)
        transformed_attrs: t.MutableStrSequenceMapping | None = None
        if source_type_norm == "oid" and target_type_norm == "rfc":
            transformed_attrs = FlextLdifUtilitiesEntry.remap_oid_rfc_attributes(
                current_attrs,
                attribute_mapping=c.Ldif.ATTRIBUTE_TRANSFORMATION_OID_TO_RFC,
                boolean_value_mapping=c.Ldif.OID_TO_RFC_BOOL,
            )
        elif source_type_norm == "rfc" and target_type_norm == "oid":
            transformed_attrs = FlextLdifUtilitiesEntry.remap_oid_rfc_attributes(
                current_attrs,
                attribute_mapping=c.Ldif.ATTRIBUTE_TRANSFORMATION_RFC_TO_OID,
                boolean_value_mapping=c.Ldif.RFC_TO_OID_BOOL,
            )
        return transformed_attrs

    @staticmethod
    def transform_schema_dn_between_oid_rfc(
        entry: p.Ldif.Entry,
        source_type_norm: str,
        target_type_norm: str,
    ) -> str | None:
        """Compute transformed schema DN between OID and RFC conventions."""
        dn_model = entry.dn
        if dn_model is None:
            return None
        dn_value = dn_model.value
        dn_lower = dn_value.lower()
        if source_type_norm == "oid" and target_type_norm == "rfc":
            if "cn=subschemasubentry" not in dn_lower:
                return None
            return dn_value.replace("cn=subschemasubentry", "cn=schema")
        if source_type_norm == "rfc" and target_type_norm == "oid":
            if "cn=schema" not in dn_lower:
                return None
            return dn_value.replace("cn=schema", "cn=subschemasubentry")
        return None

    @staticmethod
    def matches_filter(
        entry: p.Ldif.Entry,
        filter_func: Callable[[p.Ldif.Entry], bool] | None = None,
    ) -> bool:
        """Check if entry matches a filter function.

        If no filter provided, returns True (entry matches).

        Args:
            entry: LDIF entry to check
            filter_func: Optional callable that takes Entry and returns bool

        Returns:
            True if entry matches filter (or no filter provided), False otherwise

        """
        if filter_func is None:
            return True
        try:
            return filter_func(entry)
        except c.Ldif.EXC_LDIF_PARSE:
            return False

    # --- Validation helpers (called by u.model_validators) ---

    @staticmethod
    def validate_dn_format(dn_value: str) -> t.MutableSequenceOf[str]:
        """Validate DN format per RFC 4514 section 2.3, 2.4.

        Args:
            dn_value: DN string to validate

        Returns:
            List of validation violation messages (empty if valid)

        """
        violations: t.MutableSequenceOf[str] = []
        if not dn_value or not dn_value.strip():
            violations.append(
                "RFC 2849 § 2: DN is required (empty or whitespace DN)",
            )
            return violations
        components = [comp.strip() for comp in dn_value.split(",") if comp.strip()]
        if not components:
            violations.append("RFC 4514 § 2.4: DN is empty (no RDN components)")
            return violations
        for idx, comp in enumerate(components):
            if not c.Ldif.DN_COMPONENT_RE.match(comp):
                violations.append(
                    f"RFC 4514 § 2.3: Component {idx} '{comp}' invalid format",
                )
        return violations

    @staticmethod
    def validate_attributes_required(
        entry: p.Ldif.EntryValidationSubject,
    ) -> t.MutableSequenceOf[str]:
        """Validate that entry has at least one attribute per RFC 2849 section 2.

        Note: entry.attributes may be None when using model_construct (bypasses validation).
        """
        violations: t.MutableSequenceOf[str] = []
        if entry.changetype in {"delete", "moddn", "modrdn"}:
            return violations
        change_operations = getattr(entry, "change_operations", [])
        if entry.changetype == "modify" and change_operations:
            return violations
        if entry.attributes is None:
            violations.append(
                "RFC 2849 § 2: Entry must have at least one attribute (missing)",
            )
            return violations
        if not entry.attributes:
            violations.append(
                "RFC 2849 § 2: Entry must have at least one attribute (empty)",
            )
        return violations

    @staticmethod
    def validate_attribute_descriptions(
        entry: p.Ldif.EntryValidationSubject,
    ) -> t.MutableSequenceOf[str]:
        """Validate attribute descriptions per RFC 4512 section 2.5.

        Note: entry.attributes may be None when using model_construct (bypasses validation).
        """
        violations: t.MutableSequenceOf[str] = []
        if entry.attributes is None or not entry.attributes:
            return violations
        for attr_desc in entry.attributes.attributes:
            parts = attr_desc.split(";")
            base_attr = parts[0]
            if not c.Ldif.ATTRIBUTE_NAME_RE.match(base_attr):
                violations.append(
                    f"RFC 4512 § 2.5: '{base_attr}' must start with letter"
                    if not base_attr or not base_attr[0].isalpha()
                    else f"RFC 4512 § 2.5: '{base_attr}' has invalid characters",
                )
            for option in parts[1:]:
                option = option.strip()
                if not option:
                    continue
                if not c.Ldif.ATTRIBUTE_OPTION_RE.match(option):
                    violations.append(
                        f"RFC 4512 § 2.5: option '{option}' must start with letter"
                        if not option or not option[0].isalpha()
                        else f"RFC 4512 § 2.5: option '{option}' has invalid characters",
                    )
        return violations

    @staticmethod
    def validate_attribute_syntax(
        entry: p.Ldif.EntryValidationSubject,
    ) -> t.MutableSequenceOf[str]:
        """Validate attribute name/option syntax per RFC 4512 section 2.5.1-2.5.2.

        Note: entry.attributes may be None when using model_construct (bypasses validation).
        """
        violations: t.MutableSequenceOf[str] = []
        if entry.attributes is None or not entry.attributes:
            return violations
        for attr_desc in entry.attributes.attributes:
            parts = attr_desc.split(";")
            base_name = parts[0]
            if not c.Ldif.ATTRIBUTE_NAME_RE.match(base_name):
                violations.append(f"RFC 4512 § 2.5.1: '{base_name}' invalid syntax")
            if len(parts) > 1:
                invalid_options = [
                    f"RFC 4512 § 2.5.2: option '{option}' invalid syntax"
                    for option in parts[1:]
                    if option and (not c.Ldif.ATTRIBUTE_NAME_RE.match(option))
                ]
                violations.extend(invalid_options)
        return violations

    @staticmethod
    def validate_binary_options(
        entry: p.Ldif.EntryValidationSubject,
    ) -> t.MutableSequenceOf[str]:
        """Validate binary attribute options per RFC 2849 section 5.2.

        Uses compiled regex for O(1)-per-match detection instead of
        Python char-by-char ord() loops.

        Note: entry.attributes may be None when using model_construct (bypasses validation).
        """
        violations: t.MutableSequenceOf[str] = []
        if entry.attributes is None or not entry.attributes:
            return violations
        for attr_name, attr_values in entry.attributes.items():
            if ";binary" in attr_name.lower():
                continue
            for value in attr_values:
                if c.Ldif.BINARY_CHAR_RE.search(value):
                    violations.append(
                        f"RFC 2849 § 5.2: '{attr_name}' may need ';binary' option",
                    )
                    break
        return violations

    @staticmethod
    def validate_changetype(
        entry: p.Ldif.EntryValidationSubject,
    ) -> t.MutableSequenceOf[str]:
        """Validate changetype field per RFC 2849 section 5.7."""
        violations: t.MutableSequenceOf[str] = []
        if not entry.changetype:
            return violations
        valid_changetypes = {"add", "delete", "modify", "moddn", "modrdn"}
        if entry.changetype.lower() not in valid_changetypes:
            violations.append(
                f"RFC 2849 § 5.7: changetype '{entry.changetype}' invalid",
            )
        return violations

    @staticmethod
    def validate_naming_attribute(
        entry: p.Ldif.EntryValidationSubject,
        dn_value: str,
    ) -> t.MutableSequenceOf[str]:
        """Validate naming attribute presence per RFC 4512 section 2.3.

        Note: entry.attributes may be None when using model_construct (bypasses validation).
        """
        violations: t.MutableSequenceOf[str] = []
        if entry.changetype:
            return violations
        if not dn_value or entry.attributes is None or (not entry.attributes):
            return violations
        first_rdn = (
            dn_value.split(",", maxsplit=1)[0].strip()
            if "," in dn_value
            else dn_value.strip()
        )
        if "=" not in first_rdn:
            return violations
        naming_attr = first_rdn.split("=")[0].strip().lower()
        has_naming_attr = any(
            attr_name.lower() == naming_attr
            for attr_name in entry.attributes.attributes
        )
        if not has_naming_attr:
            violations.append(
                f"RFC 4512 § 2.3: Entry SHOULD have Naming attribute '{naming_attr}'",
            )
        return violations

    @staticmethod
    def validate_objectclass(
        entry: p.Ldif.EntryValidationSubject,
        dn_value: str,
    ) -> t.MutableSequenceOf[str]:
        """Validate objectClass presence per RFC 4512 section 2.4.1.

        Note: entry.attributes may be None when using model_construct (bypasses validation).
        """
        violations: t.MutableSequenceOf[str] = []
        if entry.changetype:
            return violations
        is_schema_entry = dn_value.lower().startswith(
            "cn=schema",
        ) or dn_value.lower().startswith("cn=subschema")
        if entry.attributes is None or is_schema_entry or (not entry.attributes):
            return violations
        has_objectclass = any(
            attr_name.lower() == "objectclass"
            for attr_name in entry.attributes.attributes
        )
        if not has_objectclass:
            violations.append(
                f"RFC 4512 § 2.4.1: Entry SHOULD have objectClass (DN: {dn_value})",
            )
        return violations

    # --- Server rule checkers ---

    @staticmethod
    def check_binary_option_rule(
        entry: p.Ldif.EntryValidationSubject,
        rules: FlextLdifModelsSettings.ServerValidationRules,
    ) -> t.MutableSequenceOf[str]:
        """Check binary attribute option requirement from server rules."""
        violations: t.MutableSequenceOf[str] = []
        if not rules.requires_binary_option or not entry.attributes:
            return violations
        for attr_name, attr_values in entry.attributes.items():
            if ";binary" in attr_name.lower():
                continue
            for value in attr_values:
                if any(
                    ord(char) < c.Ldif.ASCII_PRINTABLE_MIN
                    or ord(char) > c.Ldif.ASCII_PRINTABLE_MAX
                    for char in value
                ):
                    violations.append(
                        f"Server requires ';binary' option for '{attr_name}'",
                    )
                    break
        return violations

    @staticmethod
    def check_naming_attr_rule(
        entry: p.Ldif.EntryValidationSubject,
        rules: FlextLdifModelsSettings.ServerValidationRules,
        dn_value: str,
    ) -> t.MutableSequenceOf[str]:
        """Check naming attribute requirement from server rules."""
        violations: t.MutableSequenceOf[str] = []
        if not rules.requires_naming_attr or not dn_value or (not entry.attributes):
            return violations
        first_rdn = dn_value.split(",", maxsplit=1)[0].strip()
        if "=" not in first_rdn:
            return violations
        naming_attr = first_rdn.split("=")[0].strip().lower()
        has_naming_attr = any(
            attr_name.lower() == naming_attr
            for attr_name in entry.attributes.attributes
        )
        if not has_naming_attr:
            violations.append(f"Server requires naming attribute '{naming_attr}'")
        return violations

    @staticmethod
    def check_objectclass_rule(
        entry: p.Ldif.EntryValidationSubject,
        rules: FlextLdifModelsSettings.ServerValidationRules,
        dn_value: str,
    ) -> t.MutableSequenceOf[str]:
        """Check objectClass requirement from server rules."""
        violations: t.MutableSequenceOf[str] = []
        if not rules.requires_objectclass:
            return violations
        has_objectclass = (
            any(
                attr_name.lower() == "objectclass"
                for attr_name in entry.attributes.attributes
            )
            if entry.attributes
            else False
        )
        is_schema_entry = dn_value and (
            dn_value.lower().startswith("cn=schema")
            or dn_value.lower().startswith("cn=subschema")
        )
        if not has_objectclass and (not is_schema_entry):
            violations.append("Server requires objectClass attribute")
        return violations

    # --- Factory helpers ---

    @staticmethod
    def parse_validation_rules(
        validation_rules: FlextLdifModelsSettings.ServerValidationRules | t.JsonValue,
    ) -> FlextLdifModelsSettings.ServerValidationRules | None:
        """Normalize dynamic validation_rules payload to ServerValidationRules."""
        if isinstance(
            validation_rules,
            FlextLdifModelsSettings.ServerValidationRules,
        ):
            return validation_rules
        if isinstance(validation_rules, str):
            try:
                validated_json: FlextLdifModelsSettings.ServerValidationRules = (
                    FlextLdifModelsSettings.ServerValidationRules.model_validate_json(
                        validation_rules,
                    )
                )
                return validated_json
            except c.ValidationError as exc:
                FlextLdifUtilitiesEntry.logger.warning(
                    f"Failed to validate server rules from JSON string: {exc}",
                )
                return None
        if isinstance(validation_rules, Mapping):
            try:
                validated: FlextLdifModelsSettings.ServerValidationRules = (
                    FlextLdifModelsSettings.ServerValidationRules.model_validate(
                        validation_rules,
                    )
                )
                return validated
            except c.ValidationError as exc:
                FlextLdifUtilitiesEntry.logger.warning(
                    f"Failed to validate server rules from mapping: {exc}",
                )
        return None

    @staticmethod
    def normalize_unconverted_attributes(
        value: t.JsonMapping | t.JsonValue | None,
    ) -> t.Ldif.UnconvertedAttributes:
        """Normalize metadata-carried unconverted attributes to the public LDIF shape."""
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

    # --- Existing methods (already in utility) ---

    @staticmethod
    def analyze_minimal_differences(
        original: str,
        converted: str | None,
        context: str = "entry",
    ) -> t.Ldif.MutableMetadataMapping:
        """Analyze minimal differences between original and converted strings."""
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
        """Analyze DN and attribute differences for round-trip support (DRY utility)."""

        def _default_normalize(value: str) -> str:
            return value.lower()

        normalize = normalize_attr_fn or _default_normalize
        dn_differences = FlextLdifUtilitiesEntry.analyze_minimal_differences(
            original=original_dn,
            converted=cleaned_dn if cleaned_dn != original_dn else None,
            context="dn",
        )

        def extract_case_mapping(attr_name: str) -> tuple[str, str] | None:
            """Extract case mapping if different."""
            attr_str = attr_name
            canonical = normalize(attr_str)
            return (canonical, attr_str) if canonical != attr_str else None

        original_attribute_case: t.MutableStrMapping = {}
        for attr_name in entry_attrs:
            try:
                result = extract_case_mapping(attr_name)
                if result is not None:
                    key, value = result
                    original_attribute_case[key] = value
            except c.EXC_BASIC_TYPE:
                continue
        attribute_differences: MutableMapping[str, t.Ldif.MutableMetadataMapping] = {}
        original_attributes_complete: t.Ldif.MutableMetadataMapping = {}
        for attr_name, attr_values in entry_attrs.items():
            original_attr_name = attr_name
            canonical_name = normalize(original_attr_name)
            original_values_list: list[str] = []
            if isinstance(attr_values, Sequence) and (
                not isinstance(attr_values, str | bytes)
            ):
                original_values_list = [str(v) for v in attr_values if v is not None]
            elif attr_values is not None:
                original_values_list = [str(attr_values)]
            original_attributes_complete[original_attr_name] = (
                u.normalize_to_json_value(original_values_list)
            )
            converted_values = converted_attrs.get(canonical_name, [])
            original_str = f"{original_attr_name}: {', '.join(original_values_list)}"
            converted_str = (
                f"{canonical_name}: {', '.join(str(v) for v in converted_values)}"
                if converted_values
                else None
            )
            attr_diff = FlextLdifUtilitiesEntry.analyze_minimal_differences(
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
        attributes: t.MappingKV[
            str,
            t.MutableSequenceOf[str] | t.MutableSequenceOf[bytes] | str | bytes,
        ],
        boolean_attr_names: set[str],
        *,
        source_format: str = "0/1",
        target_format: str = "TRUE/FALSE",
    ) -> t.MutableStrSequenceMapping:
        """Convert boolean attribute values between formats."""
        result: t.MutableStrSequenceMapping = {}
        format_pair = (source_format, target_format)
        normalized_boolean_names = {
            attr_name.lower() for attr_name in boolean_attr_names
        }
        for attr_name in attributes:
            attr_raw_values = attributes[attr_name]
            str_values: t.MutableSequenceOf[str] = []
            if isinstance(attr_raw_values, str | bytes):
                raw_items = [attr_raw_values]
            else:
                raw_items = attr_raw_values
            for raw_item in raw_items:
                normalized_value = (
                    raw_item.decode(c.Ldif.DEFAULT_ENCODING, errors="replace")
                    if isinstance(raw_item, bytes)
                    else raw_item
                )
                if attr_name.lower() in normalized_boolean_names:
                    match format_pair:
                        case ("0/1", "TRUE/FALSE"):
                            normalized_value = (
                                "TRUE" if normalized_value == "1" else "FALSE"
                            )
                        case ("TRUE/FALSE", "0/1"):
                            normalized_value = (
                                "1" if normalized_value.upper() == "TRUE" else "0"
                            )
                        case _:
                            pass
                str_values.append(normalized_value)
            result[attr_name] = str_values
        return result

    @staticmethod
    def is_schema_entry(entry: p.Ldif.Entry, *, strict: bool = True) -> bool:
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
        entry: p.Ldif.Entry,
        settings: FlextLdifModelsSettings.EntryCriteriaConfig | None = None,
        **kwargs: str | float | bool | None,
    ) -> bool:
        """Check multiple entry criteria in one call."""
        resolved_config = (
            settings
            if settings is not None
            else FlextLdifModelsSettings.EntryCriteriaConfig.model_validate(kwargs)
        )
        checks: t.MutableSequenceOf[bool] = []
        if resolved_config.is_schema is not None:
            checks.append(
                FlextLdifUtilitiesEntry.is_schema_entry(entry)
                == resolved_config.is_schema,
            )
        if resolved_config.objectclasses:
            entry_ocs: t.StrSequence = (
                entry.attributes.get("objectClass", []) if entry.attributes else []
            )
            entry_ocs_lower = {oc.lower() for oc in entry_ocs}
            matching = [
                oc
                for oc in resolved_config.objectclasses
                if oc.lower() in entry_ocs_lower
            ]
            checks.append(
                bool(matching)
                if resolved_config.objectclass_mode == "any"
                else len(matching) == len(resolved_config.objectclasses),
            )
        if resolved_config.required_attrs:
            if not entry.attributes:
                checks.append(False)
            else:
                entry_attrs_lower = {k.lower() for k in entry.attributes.attributes}
                checks.append(
                    all(
                        a.lower() in entry_attrs_lower
                        for a in resolved_config.required_attrs
                    ),
                )
        if resolved_config.any_attrs:
            if not entry.attributes:
                checks.append(False)
            else:
                entry_attrs_lower = {k.lower() for k in entry.attributes.attributes}
                checks.append(
                    any(
                        a.lower() in entry_attrs_lower
                        for a in resolved_config.any_attrs
                    ),
                )
        if resolved_config.dn_pattern:
            dn_value = (
                entry.dn.value
                if entry.dn and getattr(entry.dn, "value", None) is not None
                else str(entry.dn)
                if entry.dn
                else ""
            )
            checks.append(
                bool(
                    c.Ldif.compile_pattern(
                        resolved_config.dn_pattern, ignorecase=True
                    ).search(dn_value),
                ),
            )
        return all(checks)

    @staticmethod
    def matches_entry_server_patterns(
        entry_dn: str,
        attributes: t.StrSequenceMapping,
        settings: FlextLdifModelsSettings.ServerPatternsConfig,
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
        if settings.dn_patterns and any(
            all(pattern in entry_dn for pattern in pattern_set)
            for pattern_set in settings.dn_patterns
        ):
            return True
        if settings.attr_prefixes and any(
            attr.startswith(prefix)
            for attr in attrs
            for prefix in settings.attr_prefixes
        ):
            return True
        if settings.attr_names and attr_names_lower & set(settings.attr_names):
            return True
        if settings.keyword_patterns:
            return any(
                keyword in attr
                for attr in attr_names_lower
                for keyword in settings.keyword_patterns
            )
        return False


__all__: list[str] = ["FlextLdifUtilitiesEntry"]
