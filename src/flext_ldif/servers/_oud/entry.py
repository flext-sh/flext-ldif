"""Oracle Unified Directory (OUD) Quirks."""

from __future__ import annotations

import json
import re
from collections.abc import Callable, Mapping

from flext_core import FlextLogger, FlextResult

from flext_ldif._models.domain import FlextLdifModelsDomains
from flext_ldif._models.metadata import FlextLdifModelsMetadata
from flext_ldif._models.settings import FlextLdifModelsSettings
from flext_ldif._utilities.metadata import FlextLdifUtilitiesMetadata
from flext_ldif.constants import c
from flext_ldif.models import m
from flext_ldif.servers._base.entry import FlextLdifServersBaseEntry
from flext_ldif.servers._oud.acl import FlextLdifServersOudAcl
from flext_ldif.servers._oud.constants import FlextLdifServersOudConstants
from flext_ldif.servers.base import FlextLdifServersBase
from flext_ldif.servers.rfc import FlextLdifServersRfc
from flext_ldif.typings import t
from flext_ldif.utilities import u

logger = FlextLogger(__name__)


class FlextLdifServersOudEntry(FlextLdifServersRfc.Entry):
    """Oracle OUD Entry Implementation (RFC 2849 + OUD Extensions)."""

    def __init__(
        self,
        entry_service: object | None = None,
        _parent_quirk: FlextLdifServersBase | None = None,
        **kwargs: str | float | bool | None,
    ) -> None:
        """Initialize OUD entry quirk."""
        filtered_kwargs: dict[str, str | float | bool | None] = {
            k: v
            for k, v in kwargs.items()
            if k != "_parent_quirk" and isinstance(v, (str, float, bool, type(None)))
        }

        entry_service_typed: object | None = (
            entry_service if entry_service is not None else None
        )

        FlextLdifServersBaseEntry.__init__(
            self,
            entry_service_typed,
            _parent_quirk=None,
            **filtered_kwargs,
        )

        if _parent_quirk is not None:
            object.__setattr__(self, "_parent_quirk", _parent_quirk)

    def can_handle(
        self,
        entry_dn: str,
        attributes: dict[str, list[str]],
    ) -> bool:
        """Check if OUD should handle this entry using pattern matching."""
        oud_constants = FlextLdifServersOudConstants

        patterns_config = FlextLdifModelsSettings.ServerPatternsConfig(
            dn_patterns=oud_constants.DN_DETECTION_PATTERNS,
            attr_prefixes=oud_constants.DETECTION_ATTRIBUTE_PREFIXES,
            attr_names=oud_constants.BOOLEAN_ATTRIBUTES,
            keyword_patterns=oud_constants.KEYWORD_PATTERNS,
        )
        return (
            u.Ldif.Entry.matches_server_patterns(
                entry_dn,
                attributes,
                patterns_config,
            )
            or "objectclass" in attributes
        )

    def parse_entry(
        self,
        entry_dn: str,
        entry_attrs: (dict[str, list[str]] | m.Ldif.Entry),
    ) -> FlextResult[m.Ldif.Entry]:
        """Parse entry with OUD-specific metadata population."""
        entry_attrs_dict: dict[str, list[str]] = {}
        if isinstance(entry_attrs, dict):
            for key, values in entry_attrs.items():
                if isinstance(values, list):
                    entry_attrs_dict[key] = [str(v) for v in values]
                elif isinstance(values, (str, bytes)):
                    entry_attrs_dict[key] = [str(values)]
                else:
                    entry_attrs_dict[key] = [str(values)]
        elif (
            isinstance(entry_attrs, m.Ldif.Entry)
            and entry_attrs.attributes
            and entry_attrs.attributes.attributes
        ):
            entry_attrs_dict = {
                k: [str(v) for v in (vs if isinstance(vs, list) else [vs])]
                for k, vs in entry_attrs.attributes.attributes.items()
            }

        result = self._create_entry(entry_dn, entry_attrs_dict)
        if result.is_failure:
            return result

        entry = result.value

        original_attribute_case: dict[str, str] = {}
        if isinstance(entry_attrs, Mapping):
            for attr_name in entry_attrs:
                if isinstance(attr_name, str):
                    original_attribute_case[attr_name.lower()] = attr_name

        original_attr_lines: list[str] = []
        for attr_name, attr_values in entry_attrs_dict.items():
            original_name = original_attribute_case.get(attr_name.lower(), attr_name)
            original_attr_lines.extend(
                f"{original_name}: {value}" for value in attr_values
            )

        metadata_config = FlextLdifModelsSettings.EntryParseMetadataConfig(
            quirk_type="oud",
            original_entry_dn=entry_dn,
            cleaned_dn=entry.dn.value if entry.dn else entry_dn,
            original_dn_line=f"dn: {entry_dn}",
            original_attr_lines=original_attr_lines,
            dn_was_base64=False,
            original_attribute_case=original_attribute_case,
        )
        metadata = FlextLdifUtilitiesMetadata.build_entry_parse_metadata(
            metadata_config,
        )

        entry.metadata = metadata

        post_result = self._hook_post_parse_entry(entry)
        if post_result.is_failure:
            return post_result
        entry = post_result.value

        finalize_result = self._hook_finalize_entry_parse(
            entry,
            entry_dn,
            entry_attrs_dict,
        )
        if finalize_result.is_failure:
            return finalize_result
        entry = finalize_result.value

        return FlextResult.ok(entry)

    def _parse_entry_from_lines(self, lines: list[str]) -> FlextResult[m.Ldif.Entry]:
        """Parse entry lines and preserve OUD metadata during entry creation."""
        dn: str = ""
        attrs: dict[str, list[str]] = {}

        for raw_line in lines:
            line = raw_line.rstrip()
            if not line or line.startswith("#"):
                continue

            if line.startswith(" ") and attrs:
                last_key = list(attrs.keys())[-1]
                if attrs[last_key]:
                    attrs[last_key][-1] += line[1:]
                continue

            if ":" not in line:
                continue

            key, _, value = line.partition(":")
            key = key.strip()
            value = value.strip()

            if key.lower() == "dn":
                dn = value
            else:
                if key not in attrs:
                    attrs[key] = []
                attrs[key].append(value)

        if not dn:
            return FlextResult[m.Ldif.Entry].fail("No DN found in entry")

        return self.parse_entry(dn, attrs)

    def _is_schema_entry(self, entry: m.Ldif.Entry) -> bool:
        """Check if entry is a schema entry - delegate to utility."""
        facade_entry = m.Ldif.Entry.model_validate(entry.model_dump())
        return u.Ldif.Entry.is_schema_entry(facade_entry, strict=False)

    def _add_original_entry_comments(
        self,
        entry_data: m.Ldif.Entry,
        write_options: m.Ldif.WriteFormatOptions | None,
    ) -> list[str]:
        """Add original entry as commented LDIF block."""
        if not (write_options and write_options.write_original_entry_as_comment):
            return []

        if not (entry_data.metadata and entry_data.metadata.write_options):
            return []

        write_opts = entry_data.metadata.write_options
        if hasattr(write_opts, "model_dump"):
            write_opts_dict = write_opts.model_dump()
        elif isinstance(write_opts, dict):
            write_opts_dict = write_opts
        else:
            write_opts_dict = {}
        original_entry_obj = write_opts_dict.get("original_entry")
        if not (original_entry_obj and isinstance(original_entry_obj, m.Ldif.Entry)):
            return []

        ldif_parts: list[str] = []
        ldif_parts.extend(
            [
                "# " + "=" * 70,
                "# ORIGINAL Entry (alternative format) (commented)",
                "# " + "=" * 70,
            ],
        )

        original_result = self._write_entry_as_comment(original_entry_obj)
        if original_result.is_success:
            ldif_parts.append(original_result.value)

        ldif_parts.extend(
            [
                "",
                "# " + "=" * 70,
                "# CONVERTED OUD Entry (active)",
                "# " + "=" * 70,
            ],
        )

        return ldif_parts

    def _apply_phase_aware_acl_handling(
        self,
        entry_data: m.Ldif.Entry,
        write_options: m.Ldif.WriteFormatOptions | None,
    ) -> m.Ldif.Entry:
        """Apply phase-aware ACL attribute commenting."""
        if not (write_options and write_options.comment_acl_in_non_acl_phases):
            return entry_data

        category = write_options.entry_category
        acl_attrs = write_options.acl_attribute_names

        if not (category and category != "acl" and acl_attrs):
            return entry_data

        acl_attrs_list = (
            list(acl_attrs)
            if isinstance(acl_attrs, (frozenset, set))
            else acl_attrs
            if isinstance(acl_attrs, list)
            else []
        )
        return self._comment_acl_attributes(entry_data, acl_attrs_list)

    @staticmethod
    def extract_and_remove_acl_attributes(
        attributes_dict: dict[str, list[str]],
        acl_attribute_names: list[str],
    ) -> tuple[dict[str, list[str]], dict[str, list[str]], set[str]]:
        """Extract ACL attributes and remove from active dict."""
        new_attrs: dict[str, list[str]] = dict(attributes_dict)
        commented_vals: dict[str, list[str]] = {}
        hidden_attrs = set()

        for acl_attr in acl_attribute_names:
            if acl_attr in new_attrs:
                acl_values = new_attrs[acl_attr]
                if isinstance(acl_values, list):
                    commented_vals[acl_attr] = list(acl_values)
                else:
                    commented_vals[acl_attr] = [str(acl_values)]

                del new_attrs[acl_attr]
                hidden_attrs.add(acl_attr.lower())

        return new_attrs, commented_vals, hidden_attrs

    @staticmethod
    def _create_write_options_with_hidden_attrs(
        write_opts: m.Ldif.WriteOptions | dict[str, t.GeneralValueType] | None,
        hidden_attrs: set[str],
    ) -> m.Ldif.WriteOptions:
        """Create WriteOptions with updated hidden attributes."""
        if not write_opts:
            return m.Ldif.WriteOptions()

        hidden_attrs_raw = getattr(write_opts, "hidden_attrs", [])
        hidden_attrs_set = (
            set(hidden_attrs_raw)
            if isinstance(hidden_attrs_raw, (list, tuple, frozenset, set))
            else set()
        )
        hidden_attrs_set.update(hidden_attrs)

        if isinstance(write_opts, m.Ldif.WriteOptions):
            update_dict: dict[str, t.GeneralValueType] = {
                "hidden_attrs": list(hidden_attrs_set)
            }
            return write_opts.model_copy(update=update_dict)

        if isinstance(write_opts, dict):
            write_opts_dict: dict[str, t.GeneralValueType] = {
                "hidden_attrs": list(hidden_attrs_set),
            }
            for field in ["line_width", "indent", "sort_attributes"]:
                if field in write_opts:
                    write_opts_dict[field] = write_opts[field]
            return m.Ldif.WriteOptions.model_validate(write_opts_dict)

        if hasattr(write_opts, "model_dump"):
            write_opts_dict_raw = write_opts.model_dump()
            filtered_dict: dict[str, t.GeneralValueType] = {
                "hidden_attrs": list(hidden_attrs_set)
            }
            for field in ["line_width", "indent", "sort_attributes"]:
                if field in write_opts_dict_raw:
                    filtered_dict[field] = write_opts_dict_raw[field]
            return m.Ldif.WriteOptions.model_validate(filtered_dict)

        return m.Ldif.WriteOptions(hidden_attrs=list(hidden_attrs_set))

    @staticmethod
    def update_metadata_with_commented_acls(
        metadata: FlextLdifModelsDomains.QuirkMetadata,
        acl_attribute_names: list[str],
        commented_acl_values: dict[str, list[str]],
        hidden_attrs: set[str],
        entry_attributes_dict: dict[str, list[str]],
    ) -> FlextLdifModelsDomains.QuirkMetadata:
        """Update metadata with commented ACL information."""
        metadata_typed: FlextLdifModelsDomains.QuirkMetadata = metadata
        current_extensions: dict[str, t.MetadataAttributeValue] = (
            dict(metadata_typed.extensions) if metadata_typed.extensions else {}
        )

        new_write_options = (
            FlextLdifServersOudEntry._create_write_options_with_hidden_attrs(
                metadata_typed.write_options,
                hidden_attrs,
            )
        )

        update_dict: dict[str, t.GeneralValueType] = {
            "write_options": new_write_options
        }
        metadata_typed = metadata_typed.model_copy(update=update_dict)

        if commented_acl_values:
            converted_attrs_list: list[str] = list(commented_acl_values.keys())

            converted_attrs_typed: t.MetadataAttributeValue = list(converted_attrs_list)
            current_extensions["converted_attributes"] = converted_attrs_typed

            current_extensions["commented_attribute_values"] = json.dumps(
                commented_acl_values,
            )

        commented_attrs_raw = current_extensions.get("acl_commented_attributes", [])
        commented_attrs: list[str] = (
            [str(x) for x in commented_attrs_raw]
            if isinstance(commented_attrs_raw, list)
            else []
        )

        for acl_attr in acl_attribute_names:
            if acl_attr in entry_attributes_dict and acl_attr not in commented_attrs:
                commented_attrs.append(acl_attr)

        if commented_attrs:
            commented_attrs_typed: t.MetadataAttributeValue = list(commented_attrs)
            current_extensions["acl_commented_attributes"] = commented_attrs_typed

        update_dict_final: dict[str, t.GeneralValueType] = {
            "extensions": current_extensions,
            "write_options": new_write_options,
        }
        return metadata_typed.model_copy(update=update_dict_final)

    @staticmethod
    def _comment_acl_attributes(
        entry_data: m.Ldif.Entry,
        acl_attribute_names: list[str],
    ) -> m.Ldif.Entry:
        """Comment out ACL attributes by removing them from attributes dict and storing in metadata."""
        if not entry_data.attributes or not acl_attribute_names:
            return entry_data

        existing_metadata = entry_data.metadata
        if not existing_metadata:
            existing_metadata = m.Ldif.QuirkMetadata.create_for("oud")

        new_attributes_dict, commented_acl_values, hidden_attrs = (
            FlextLdifServersOudEntry.extract_and_remove_acl_attributes(
                entry_data.attributes.attributes,
                acl_attribute_names,
            )
        )

        updated_metadata = FlextLdifServersOudEntry.update_metadata_with_commented_acls(
            existing_metadata,
            acl_attribute_names,
            commented_acl_values,
            hidden_attrs,
            entry_data.attributes.attributes,
        )

        return entry_data.model_copy(
            update={
                "attributes": m.Ldif.Attributes(
                    attributes=new_attributes_dict,
                    attribute_metadata=entry_data.attributes.attribute_metadata,
                    metadata=entry_data.attributes.metadata,
                ),
                "metadata": updated_metadata,
            },
        )

    def _normalize_aci_value(
        self,
        aci_value: str,
        _base_dn: str | None,
        _dn_registry: m.Ldif.DnRegistry | None,
    ) -> tuple[str, bool]:
        """Normalize ACI value DNs (already RFC canonical, no changes needed)."""
        return aci_value, False

    def _extract_acl_metadata(
        self,
        entry_data: m.Ldif.Entry,
    ) -> tuple[str | None, m.Ldif.DnRegistry | None]:
        """Extract base_dn and dn_registry from entry metadata for ACL processing."""
        base_dn: str | None = None
        dn_registry: m.Ldif.DnRegistry | None = None

        if entry_data.metadata and entry_data.metadata.write_options:
            base_dn_value = getattr(
                entry_data.metadata.write_options,
                "base_dn",
                None,
            )
            if isinstance(base_dn_value, str):
                base_dn = base_dn_value

            dn_registry_value = getattr(
                entry_data.metadata.write_options,
                "dn_registry",
                None,
            )
            if isinstance(dn_registry_value, m.Ldif.DnRegistry):
                dn_registry = dn_registry_value

        if base_dn is None and entry_data.metadata and entry_data.metadata.extensions:
            extensions = entry_data.metadata.extensions

            base_dn_ext = extensions.get("base_dn")
            if isinstance(base_dn_ext, str):
                base_dn = base_dn_ext
            dn_registry_ext = extensions.get("dn_registry")
            if isinstance(dn_registry_ext, m.Ldif.DnRegistry):
                dn_registry = dn_registry_ext

        return base_dn, dn_registry

    def _apply_original_acl_format_as_name(
        self,
        entry_data: m.Ldif.Entry,
    ) -> m.Ldif.Entry:
        """Replace ACI name with original ACL format string from metadata."""
        if not entry_data.attributes or not entry_data.attributes.attributes:
            return entry_data
        if entry_data.metadata is None or entry_data.metadata.extensions is None:
            return entry_data

        original_format = getattr(
            entry_data.metadata.extensions,
            c.Ldif.MetadataKeys.ACL_ORIGINAL_FORMAT,
            None,
        )
        if not isinstance(original_format, str) or not original_format:
            return entry_data

        ascii_printable_min = 0x20
        ascii_printable_max = 0x7E
        sanitized = "".join(
            ch
            if ascii_printable_min <= ord(ch) <= ascii_printable_max and ch != '"'
            else " "
            for ch in original_format
        ).strip()

        if not sanitized:
            return entry_data

        acl_name_pattern = re.compile(r'acl\s+"[^"]*"')
        replacement = f'acl "{sanitized}"'

        updated_attrs = dict(entry_data.attributes.attributes)
        for attr_name in ("aci", "orclaci"):
            if attr_name not in updated_attrs:
                continue
            values = updated_attrs[attr_name]
            if not isinstance(values, list):
                continue
            updated_attrs[attr_name] = [
                acl_name_pattern.sub(replacement, str(v)) if isinstance(v, str) else v
                for v in values
            ]

        new_attributes = entry_data.attributes.model_copy(
            update={"attributes": updated_attrs},
        )
        return entry_data.model_copy(update={"attributes": new_attributes})

    def _normalize_acl_dns(
        self,
        entry_data: m.Ldif.Entry,
    ) -> m.Ldif.Entry:
        """Normalize and filter DNs in ACL attribute values (userdn/groupdn inside ACL strings)."""
        if not entry_data.attributes or not entry_data.attributes.attributes:
            return entry_data

        base_dn, dn_registry = self._extract_acl_metadata(entry_data)

        attrs = entry_data.attributes.attributes
        if "aci" not in attrs:
            return entry_data

        aci_values = attrs["aci"]
        if not aci_values:
            return entry_data

        normalized_aci_values: list[str] = []
        for aci in aci_values:
            aci_str = aci if isinstance(aci, str) else str(aci)
            normalized_aci, was_filtered = self._normalize_aci_value(
                aci_str,
                base_dn,
                dn_registry,
            )

            if not was_filtered and normalized_aci:
                normalized_aci_values.append(normalized_aci)

        if normalized_aci_values != aci_values:
            new_attrs = dict(entry_data.attributes.attributes)
            new_attrs["aci"] = normalized_aci_values
            entry_data.attributes.attributes = new_attrs

        return entry_data

    def _restore_entry_from_metadata(
        self,
        entry_data: m.Ldif.Entry,
    ) -> m.Ldif.Entry:
        """Restore original DN and attributes using generic utilities."""
        if not (entry_data.metadata and entry_data.metadata.extensions):
            return entry_data
        ext = entry_data.metadata.extensions

        mk = c.Ldif.MetadataKeys
        if (
            (original_dn := ext.get(mk.ORIGINAL_DN_COMPLETE))
            and isinstance(original_dn, str)
            and entry_data.dn
        ):
            dn_diff = ext.get(mk.MINIMAL_DIFFERENCES_DN, {})
            if isinstance(dn_diff, dict):
                has_diff = dn_diff.get(mk.HAS_DIFFERENCES, False)
                if has_diff:
                    entry_data = entry_data.model_copy(
                        update={
                            "dn": m.Ldif.DN(value=original_dn),
                        },
                    )

        original_case_map = (
            entry_data.metadata.original_attribute_case if entry_data.metadata else None
        )
        if (
            entry_data.attributes
            and original_case_map
            and isinstance(original_case_map, dict)
            and (
                orig_attrs := ext.get(c.Ldif.MetadataKeys.ORIGINAL_ATTRIBUTES_COMPLETE)
            )
            and isinstance(orig_attrs, dict)
        ):
            restored: dict[str, list[str]] = {}
            for attr_name, attr_values in entry_data.attributes.attributes.items():
                orig_case_raw = original_case_map.get(
                    attr_name.lower(),
                    attr_name,
                )
                orig_case: str = str(orig_case_raw) if orig_case_raw else attr_name

                if orig_case in orig_attrs:
                    val = orig_attrs[orig_case]
                    restored[orig_case] = (
                        [str(i) for i in val]
                        if isinstance(val, (list, tuple))
                        else [str(val)]
                    )
                else:
                    restored[orig_case] = (
                        [str(i) for i in attr_values]
                        if isinstance(attr_values, list)
                        else [str(attr_values)]
                    )

            if restored:
                entry_data = entry_data.model_copy(
                    update={
                        "attributes": m.Ldif.Attributes(
                            attributes=restored,
                            attribute_metadata=entry_data.attributes.attribute_metadata,
                            metadata=entry_data.attributes.metadata,
                        ),
                    },
                )

        return entry_data

    def _write_entry(
        self,
        entry_data: m.Ldif.Entry,
    ) -> FlextResult[str]:
        """Write Entry to LDIF with OUD-specific formatting + phase-aware ACL handling."""
        hook_result = self._hook_pre_write_entry(entry_data)
        if hook_result.is_failure:
            return FlextResult[str].fail(
                f"Pre-write hook failed: {hook_result.error}",
            )
        normalized_entry = hook_result.value

        entry_to_write = self._restore_entry_from_metadata(normalized_entry)

        write_options = FlextLdifUtilitiesMetadata.extract_write_options(
            entry_to_write,
        )
        if write_options is None and entry_data.metadata:
            raw_wo = entry_data.metadata.write_options
            if isinstance(raw_wo, dict):
                inner = raw_wo.get("write_options")
                if isinstance(inner, FlextLdifModelsSettings.WriteFormatOptions):
                    write_options = inner

        ldif_parts: list[str] = []
        ldif_parts.extend(
            self._add_original_entry_comments(entry_data, write_options),
        )

        entry_data = self._apply_phase_aware_acl_handling(entry_data, write_options)

        if FlextLdifServersOudConstants.ACL_NORMALIZE_DNS_IN_VALUES:
            entry_data = self._normalize_acl_dns(entry_data)

        if write_options and write_options.use_original_acl_format_as_name:
            entry_data = self._apply_original_acl_format_as_name(
                entry_data,
            )

        return (
            super()
            ._write_entry(entry_data)
            .map(
                lambda ldif_text: u.Ldif.Writer.finalize_ldif_text(
                    ldif_parts + [ldif_text]
                ),
            )
        )

    def _write_entry_as_comment(
        self,
        entry_data: m.Ldif.Entry,
    ) -> FlextResult[str]:
        """Write entry as commented LDIF (each line prefixed with '# ')."""
        return (
            super()
            ._write_entry(entry_data)
            .map(
                lambda ldif_text: "\n".join(
                    f"# {line}" for line in ldif_text.split("\n")
                ),
            )
        )

    def _add_transformation_comments(
        self,
        comment_lines: list[str],
        entry: m.Ldif.Entry,
        format_options: m.Ldif.WriteFormatOptions | None = None,
    ) -> None:
        """Add transformation comments for attribute changes, including OUD-specific ACL handling."""
        if not entry.metadata:
            return

        acl_attr_names_to_skip = self._add_oud_acl_comments(
            comment_lines,
            entry,
            format_options,
        )

        processed_attrs: set[str] = set()
        if entry.metadata.attribute_transformations:
            attr_names = [
                attr_name
                for attr_name in entry.metadata.attribute_transformations
                if attr_name.lower() not in acl_attr_names_to_skip
            ]
            ordered_attr_names = self._determine_attribute_order(
                attr_names,
                format_options,
            )

            for attr_name in ordered_attr_names:
                transformation = entry.metadata.attribute_transformations[attr_name]
                transformation_type = transformation.transformation_type.upper()

                comment_type = (
                    "TRANSFORMED"
                    if transformation_type in {"MODIFIED", "TRANSFORMED"}
                    else transformation_type
                )
                self._add_attribute_transformation_comments(
                    comment_lines,
                    attr_name,
                    transformation,
                    comment_type,
                )
                processed_attrs.add(attr_name.lower())

        if (
            format_options
            and format_options.write_removed_attributes_as_comments
            and entry.metadata.removed_attributes
        ):
            removed_attrs_dict = entry.metadata.removed_attributes.model_dump()
            removed_attr_names: list[str] = [
                str(attr_name)
                for attr_name in removed_attrs_dict
                if isinstance(attr_name, str)
                and attr_name.lower() not in acl_attr_names_to_skip
            ]
            ordered_removed_attrs = self._determine_attribute_order(
                removed_attr_names,
                format_options,
            )

            for attr_name in ordered_removed_attrs:
                if attr_name.lower() in processed_attrs:
                    continue

                removed_values = entry.metadata.removed_attributes[attr_name]
                if isinstance(removed_values, list):
                    comment_lines.extend(
                        f"# [REMOVED] {attr_name}: {value}" for value in removed_values
                    )
                else:
                    comment_lines.append(
                        f"# [REMOVED] {attr_name}: {removed_values}",
                    )

        if comment_lines:
            comment_lines.append("")

    def _collect_acl_from_transformations(
        self,
        entry: m.Ldif.Entry,
        acl_comments_dict: dict[str, list[str]],
        acl_attr_names_to_skip: set[str],
    ) -> None:
        """Collect ACL comments from attribute_transformations with SKIP_TO_04."""
        if not entry.metadata or not entry.metadata.attribute_transformations:
            return

        acl_attr_set = {"aci", "orclaci", "orclentrylevelaci"}
        for (
            attr_name,
            transformation,
        ) in entry.metadata.attribute_transformations.items():
            is_skip_to_04 = (
                transformation.reason and "SKIP_TO_04" in transformation.reason.upper()
            )
            if is_skip_to_04 and attr_name.lower() in acl_attr_set:
                acl_attr_names_to_skip.add(attr_name.lower())
                if attr_name not in acl_comments_dict:
                    acl_comments_dict[attr_name] = []
                for acl_value in transformation.original_values:
                    acl_comments_dict[attr_name].extend([
                        f"# [REMOVED] {attr_name}: {acl_value}",
                        f"# [SKIP_TO_04] {attr_name}: {acl_value}",
                    ])

    @staticmethod
    def _normalize_acl_values(
        acl_values_raw: object,
    ) -> list[str] | str | m.Ldif.Acl:
        """Normalize ACL values to expected type for comment generation."""
        if isinstance(acl_values_raw, str):
            return acl_values_raw
        if isinstance(acl_values_raw, list):
            return [str(v) for v in acl_values_raw]
        if isinstance(acl_values_raw, m.Ldif.Acl):
            return acl_values_raw
        return str(acl_values_raw)

    @staticmethod
    def _parse_commented_values(
        commented_raw: object,
    ) -> dict[str, t.GeneralValueType] | None:
        """Parse commented ACL values from raw storage format."""
        if isinstance(commented_raw, str):
            result = json.loads(commented_raw)
            if isinstance(result, dict):
                return result
            return None
        if isinstance(commented_raw, dict):
            return commented_raw
        return None

    def _collect_acl_from_extensions(
        self,
        entry: m.Ldif.Entry,
        acl_comments_dict: dict[str, list[str]],
        acl_attr_names_to_skip: set[str],
    ) -> None:
        """Collect ACL comments from extensions.commented_attribute_values."""
        if not entry.metadata or not entry.metadata.extensions:
            return

        commented_acl_values_raw = entry.metadata.extensions.get(
            "commented_attribute_values",
        )
        if not commented_acl_values_raw:
            return

        commented_acl_values = self._parse_commented_values(commented_acl_values_raw)
        if not commented_acl_values:
            return

        original_acl_attr = self._get_original_acl_attr(entry)
        for acl_attr_name, acl_values_raw in commented_acl_values.items():
            if acl_attr_name.lower() in acl_attr_names_to_skip:
                continue
            acl_attr_names_to_skip.add(acl_attr_name.lower())
            sort_key = original_acl_attr or acl_attr_name
            if sort_key not in acl_comments_dict:
                acl_comments_dict[sort_key] = []
            acl_values = self._normalize_acl_values(acl_values_raw)
            self._add_acl_value_comments(
                acl_comments_dict[sort_key],
                original_acl_attr,
                acl_attr_name,
                acl_values,
            )

    def _add_acl_value_comments(
        self,
        comments: list[str],
        original_attr: str,
        attr_name: str,
        acl_values: list[str] | str | m.Ldif.Acl,
    ) -> None:
        """Add TRANSFORMED and SKIP_TO_04 comments for ACL values."""
        if isinstance(acl_values, list):
            for acl_value in acl_values:
                comments.extend([
                    f"# [TRANSFORMED] {original_attr}: {acl_value}",
                    f"# [SKIP_TO_04] {attr_name}: {acl_value}",
                ])
        else:
            acl_val_str = str(acl_values)
            comments.extend([
                f"# [TRANSFORMED] {original_attr}: {acl_val_str}",
                f"# [SKIP_TO_04] {attr_name}: {acl_val_str}",
            ])

    def _add_oud_acl_comments(
        self,
        comment_lines: list[str],
        entry: m.Ldif.Entry,
        format_options: m.Ldif.WriteFormatOptions | None = None,
    ) -> set[str]:
        """Add OUD-specific ACL comments for phases 01-03."""
        acl_attr_names_to_skip: set[str] = set()
        if not entry.metadata:
            return acl_attr_names_to_skip

        acl_comments_dict: dict[str, list[str]] = {}

        self._collect_acl_from_transformations(
            entry,
            acl_comments_dict,
            acl_attr_names_to_skip,
        )
        self._collect_acl_from_extensions(
            entry,
            acl_comments_dict,
            acl_attr_names_to_skip,
        )

        if acl_comments_dict:
            acl_attr_names = list(acl_comments_dict.keys())
            ordered_acl_attrs = self._determine_attribute_order(
                acl_attr_names,
                format_options,
            )
            for attr_name in ordered_acl_attrs:
                if attr_name in acl_comments_dict:
                    comment_lines.extend(acl_comments_dict[attr_name])

        return acl_attr_names_to_skip

    def _get_original_acl_attr(self, entry: m.Ldif.Entry) -> str:
        """Get original ACL attribute name (orclaci) from transformations or metadata."""
        if entry.metadata and entry.metadata.attribute_transformations:
            for (
                attr_name,
                transformation,
            ) in entry.metadata.attribute_transformations.items():
                if (
                    attr_name.lower() in {"aci", "orclaci"}
                    and transformation.target_name
                    and transformation.target_name.lower() == "aci"
                ):
                    return attr_name

        if entry.metadata and entry.metadata.extensions:
            acl_original_format = entry.metadata.extensions.get(
                "original_format",
            )
            if acl_original_format and "orclaci:" in str(acl_original_format):
                return "orclaci"

        return "orclaci"

    def generate_entry_comments(
        self,
        entry: m.Ldif.Entry,
        format_options: m.Ldif.WriteFormatOptions | None = None,
    ) -> str:
        """Generate LDIF comments for transformations, including OUD-specific ACL handling."""
        if not format_options:
            return ""

        comment_lines: list[str] = []

        if format_options.write_transformation_comments:
            self._add_transformation_comments(comment_lines, entry, format_options)

        if format_options.write_rejection_reasons:
            self._add_rejection_reason_comments(comment_lines, entry)

        return "\n".join(comment_lines) + "\n" if comment_lines else ""

    def _normalize_aci_value_simple(self, value: object) -> list[str] | str | None:
        """Normalize ACI value to list[str] | str | None."""
        if isinstance(value, list):
            return [str(v) for v in value]
        if isinstance(value, str):
            return value
        if value is None:
            return None
        return str(value)

    def _find_aci_in_dict(
        self,
        attrs: Mapping[str, object] | None,
    ) -> list[str] | str | None:
        """Find ACI value in dictionary (case-insensitive)."""
        if not attrs:
            return None
        for key, value in attrs.items():
            if key.lower() == "aci":
                return self._normalize_aci_value_simple(value)
        return None

    def _find_aci_values(
        self,
        entry: m.Ldif.Entry,
        original_attrs: t.Ldif.CommonDict.AttributeDictGeneric,
    ) -> list[str] | str | None:
        """Find ACI values from entry or original_attrs."""
        aci_values = self._normalize_aci_value_simple(
            original_attrs.get("aci") if original_attrs else None,
        )

        if not aci_values and entry.attributes and entry.attributes.attributes:
            aci_values = self._normalize_aci_value_simple(
                entry.attributes.attributes.get("aci"),
            )

        if not aci_values:
            aci_values = self._find_aci_in_dict(original_attrs)
            if not aci_values and entry.attributes and entry.attributes.attributes:
                aci_values = self._find_aci_in_dict(entry.attributes.attributes)

        return aci_values

    def _process_parsed_acl_extensions(
        self,
        acl_extensions: dict[str, t.MetadataAttributeValue],
        current_extensions: dict[str, t.MetadataAttributeValue],
    ) -> None:
        """Process parsed ACL extensions and add to current extensions."""
        mk = c.Ldif.MetadataKeys
        key_mapping: dict[str, str] = {
            "targattrfilters": mk.ACL_TARGETATTR_FILTERS,
            "targetcontrol": mk.ACL_TARGET_CONTROL,
            "extop": mk.ACL_EXTOP,
            "ip": mk.ACL_BIND_IP_FILTER,
            "dns": mk.ACL_TARGETSCOPE,
            "dayofweek": mk.ACL_NUMBERING,
            "timeofday": mk.ACL_BINDMODE,
            "authmethod": mk.ACL_SOURCE_PERMISSIONS,
            "ssf": mk.ACL_SSFS,
            mk.ACL_TARGETATTR_FILTERS: mk.ACL_TARGETATTR_FILTERS,
            mk.ACL_TARGET_CONTROL: mk.ACL_TARGET_CONTROL,
            mk.ACL_EXTOP: mk.ACL_EXTOP,
            mk.ACL_BIND_IP_FILTER: mk.ACL_BIND_IP_FILTER,
            mk.ACL_TARGETSCOPE: mk.ACL_TARGETSCOPE,
            mk.ACL_NUMBERING: mk.ACL_NUMBERING,
            mk.ACL_BINDMODE: mk.ACL_BINDMODE,
            mk.ACL_SOURCE_PERMISSIONS: mk.ACL_SOURCE_PERMISSIONS,
            mk.ACL_SSFS: mk.ACL_SSFS,
        }
        known_keys = {
            mk.ACL_TARGETATTR_FILTERS,
            mk.ACL_TARGET_CONTROL,
            mk.ACL_EXTOP,
            mk.ACL_BIND_IP_FILTER,
            mk.ACL_TARGETSCOPE,
            mk.ACL_NUMBERING,
            mk.ACL_BINDMODE,
            mk.ACL_SOURCE_PERMISSIONS,
            mk.ACL_SSFS,
        }
        for key, value in acl_extensions.items():
            key_lower = key.lower()
            mapped_key = key_mapping.get(key) or key_mapping.get(key_lower)
            if mapped_key is None and key in known_keys:
                mapped_key = key
            final_key = mapped_key or key

            if isinstance(value, (str, int, float, bool, type(None))):
                current_extensions[final_key] = value
            elif isinstance(value, (list, tuple)):
                value_list: list[t.ScalarValue] = [
                    item
                    if isinstance(item, (str, int, float, bool, type(None)))
                    else str(item)
                    for item in value
                ]
                current_extensions[final_key] = value_list
            elif isinstance(value, dict):
                value_dict_inner: dict[str, str | int | float | bool | None] = {}
                for k, v in value.items():
                    if isinstance(v, (str, int, float, bool, type(None))):
                        value_dict_inner[k] = v
                    else:
                        value_dict_inner[k] = str(v)

                value_dict_typed: t.MetadataAttributeValue = dict(value_dict_inner)
                current_extensions[final_key] = value_dict_typed
            else:
                current_extensions[final_key] = str(value)

    def _process_aci_list_for_finalize(
        self,
        aci_values: list[str] | str,
        acl_quirk: FlextLdifServersOudAcl,
        current_extensions: dict[str, t.MetadataAttributeValue],
    ) -> None:
        """Process list of ACI values and extract metadata."""
        aci_list = (
            list(aci_values)
            if isinstance(aci_values, (list, tuple))
            else [str(aci_values)]
        )
        for aci_value in aci_list:
            if not isinstance(aci_value, str):
                continue
            normalized_aci = aci_value.strip()
            if not normalized_aci.startswith("aci:"):
                normalized_aci = f"aci: {normalized_aci}"

            acl_result = acl_quirk.parse(normalized_aci)
            if acl_result.is_success:
                acl_model = acl_result.value
                if acl_model.metadata and acl_model.metadata.extensions:
                    acl_ext_raw = (
                        acl_model.metadata.extensions.model_dump()
                        if hasattr(acl_model.metadata.extensions, "model_dump")
                        else dict(acl_model.metadata.extensions)
                    )

                    acl_extensions: dict[str, t.MetadataAttributeValue] = dict(
                        acl_ext_raw,
                    )
                    self._process_parsed_acl_extensions(
                        acl_extensions,
                        current_extensions,
                    )

    def _merge_acl_metadata_to_entry(
        self,
        entry: m.Ldif.Entry,
        acl_metadata_extensions: dict[str, t.MetadataAttributeValue],
    ) -> m.Ldif.Entry:
        """Merge ACL metadata extensions into entry metadata."""
        if not acl_metadata_extensions:
            return entry

        if entry.metadata:
            current_extensions: dict[str, t.MetadataAttributeValue]
            if isinstance(
                entry.metadata.extensions,
                FlextLdifModelsMetadata.DynamicMetadata,
            ):
                current_extensions_dict = entry.metadata.extensions.model_dump(
                    exclude_unset=True,
                )
                current_extensions = current_extensions_dict
            elif isinstance(entry.metadata.extensions, dict):
                current_extensions = entry.metadata.extensions
            else:
                current_extensions = {}

            current_extensions.update(acl_metadata_extensions)
            merged_extensions = FlextLdifModelsMetadata.DynamicMetadata.from_dict(
                current_extensions,
            )
            return entry.model_copy(
                update={
                    "metadata": entry.metadata.model_copy(
                        update={"extensions": merged_extensions},
                        deep=True,
                    ),
                },
                deep=True,
            )

        entry_metadata = m.Ldif.QuirkMetadata.create_for(
            "oud",
            extensions=FlextLdifModelsMetadata.DynamicMetadata.from_dict(
                acl_metadata_extensions,
            ),
        )
        return entry.model_copy(update={"metadata": entry_metadata}, deep=True)

    def _extract_acl_metadata_from_dynamic(
        self,
        acl_extensions: FlextLdifModelsMetadata.DynamicMetadata,
        acl_metadata_extensions: dict[str, t.MetadataAttributeValue],
    ) -> None:
        """Extract ACL metadata from DynamicMetadata extensions."""
        mk = c.Ldif.MetadataKeys

        key_mapping: dict[str, str] = {
            "extop": mk.ACL_EXTOP,
            "ip": mk.ACL_BIND_IP_FILTER,
            "dns": mk.ACL_BIND_DNS,
            "dayofweek": mk.ACL_BIND_DAYOFWEEK,
            "timeofday": mk.ACL_BIND_TIMEOFDAY,
            "authmethod": "acl:vendor:bind_authmethod",
            "ssf": "acl:vendor:bind_ssf",
            "targetcontrol": "targetcontrol",
            "targetscope": "targetscope",
            "targattrfilters": mk.ACL_TARGETATTR_FILTERS,
        }
        for src_key, dest_key in key_mapping.items():
            value_raw = acl_extensions.get(src_key)
            if value_raw is not None:
                if isinstance(value_raw, (str, int, float, bool, type(None))):
                    acl_metadata_extensions[dest_key] = value_raw
                elif isinstance(value_raw, (list, tuple)):
                    value_list: list[t.ScalarValue] = [
                        item
                        if isinstance(item, (str, int, float, bool, type(None)))
                        else str(item)
                        for item in value_raw
                    ]
                    acl_metadata_extensions[dest_key] = value_list
                elif isinstance(value_raw, dict):
                    value_dict_1: dict[str, str | int | float | bool | None] = {}
                    for k, v in value_raw.items():
                        if isinstance(v, (str, int, float, bool, type(None))):
                            value_dict_1[k] = v
                        else:
                            value_dict_1[k] = str(v)

                    value_dict_typed_1: t.MetadataAttributeValue = dict(value_dict_1)
                    acl_metadata_extensions[dest_key] = value_dict_typed_1
                else:
                    acl_metadata_extensions[dest_key] = str(value_raw)

    def _extract_acl_metadata_from_dict(
        self,
        acl_extensions: dict[str, t.MetadataAttributeValue],
        acl_metadata_extensions: dict[str, t.MetadataAttributeValue],
    ) -> None:
        """Extract ACL metadata from dict extensions."""
        mk = c.Ldif.MetadataKeys
        key_mapping: dict[str, str] = {
            "extop": mk.ACL_EXTOP,
            "ip": mk.ACL_BIND_IP_FILTER,
            "dns": mk.ACL_BIND_DNS,
            "dayofweek": mk.ACL_BIND_DAYOFWEEK,
            "timeofday": mk.ACL_BIND_TIMEOFDAY,
            "authmethod": "acl:vendor:bind_authmethod",
            "ssf": "acl:vendor:bind_ssf",
            "targetcontrol": "targetcontrol",
            "targetscope": "targetscope",
            "targattrfilters": mk.ACL_TARGETATTR_FILTERS,
        }
        for src_key, dest_key in key_mapping.items():
            value_raw = acl_extensions.get(src_key)
            if value_raw is not None:
                if isinstance(value_raw, (str, int, float, bool, type(None))):
                    acl_metadata_extensions[dest_key] = value_raw
                elif isinstance(value_raw, (list, tuple)):
                    value_list: list[t.ScalarValue] = [
                        item
                        if isinstance(item, (str, int, float, bool, type(None)))
                        else str(item)
                        for item in value_raw
                    ]
                    acl_metadata_extensions[dest_key] = value_list
                elif isinstance(value_raw, dict):
                    value_dict_2: dict[str, str | int | float | bool | None] = {}
                    for k, v in value_raw.items():
                        if isinstance(v, (str, int, float, bool, type(None))):
                            value_dict_2[k] = v
                        else:
                            value_dict_2[k] = str(v)

                    value_dict_typed_2: t.MetadataAttributeValue = dict(value_dict_2)
                    acl_metadata_extensions[dest_key] = value_dict_typed_2
                else:
                    acl_metadata_extensions[dest_key] = str(value_raw)

    def _process_single_aci_value(
        self,
        aci_value: str,
        acl_metadata_extensions: dict[str, t.MetadataAttributeValue],
    ) -> FlextResult[bool]:
        """Process single ACI value, extract metadata, return has_macros flag."""
        has_macros = bool(re.search(r"\(\$dn\)|\[\$dn\]|\(\$attr\.", aci_value))

        validation_result = self._validate_aci_macros(aci_value)
        if validation_result.is_failure:
            return FlextResult[bool].fail(
                f"ACI macro validation failed: {validation_result.error}",
            )

        acl_quirk = FlextLdifServersOudAcl()
        normalized_aci = aci_value.strip()
        if not normalized_aci.startswith("aci:"):
            normalized_aci = f"aci: {normalized_aci}"

        parse_result = acl_quirk.parse(normalized_aci)
        if parse_result.is_success:
            parsed_acl = parse_result.value
            if parsed_acl.metadata and parsed_acl.metadata.extensions:
                acl_extensions = parsed_acl.metadata.extensions
                if isinstance(acl_extensions, FlextLdifModelsMetadata.DynamicMetadata):
                    self._extract_acl_metadata_from_dynamic(
                        acl_extensions,
                        acl_metadata_extensions,
                    )
                elif isinstance(acl_extensions, dict):
                    self._extract_acl_metadata_from_dict(
                        acl_extensions,
                        acl_metadata_extensions,
                    )

        return FlextResult.ok(has_macros)

    def _hook_post_parse_entry(
        self,
        entry: m.Ldif.Entry,
    ) -> FlextResult[m.Ldif.Entry]:
        """Hook: Validate OUD ACI macros after parsing Entry."""
        attrs_dict = entry.attributes.attributes if entry.attributes is not None else {}

        aci_attrs = attrs_dict.get("aci")
        if aci_attrs and isinstance(aci_attrs, (list, tuple)):
            has_macros = False
            acl_metadata_extensions: dict[str, t.MetadataAttributeValue] = {}

            for aci_value in aci_attrs:
                if isinstance(aci_value, str):
                    process_result = self._process_single_aci_value(
                        aci_value,
                        acl_metadata_extensions,
                    )
                    if process_result.is_failure:
                        return FlextResult[m.Ldif.Entry].fail(
                            process_result.error or "ACI processing failed",
                        )
                    if process_result.value:
                        has_macros = True

            if has_macros:
                max_len = FlextLdifServersOudConstants.MAX_LOG_LINE_LENGTH
                aci_list = (
                    list(aci_attrs)
                    if isinstance(aci_attrs, (list, tuple))
                    else [str(aci_attrs)]
                )
                logger.debug(
                    "Entry contains OUD ACI macros - preserved for runtime expansion",
                    entry_dn=entry.dn.value if entry.dn else None,
                    aci_count=len(aci_list),
                    aci_preview=[
                        s[:max_len] for s in aci_list[:10] if isinstance(s, str)
                    ],
                )

            entry = self._merge_acl_metadata_to_entry(entry, acl_metadata_extensions)

        return FlextResult[m.Ldif.Entry].ok(entry)

    def _validate_aci_macros(self, _aci_value: str) -> FlextResult[bool]:
        """Validate OUD ACI macro consistency rules (no-op)."""
        return FlextResult[bool].ok(value=True)

    @staticmethod
    def _hook_pre_write_entry_static(
        entry: m.Ldif.Entry,
        validate_aci_macros: Callable[[str], FlextResult[bool]],
        correct_rfc_syntax_in_attributes: Callable[
            [t.Ldif.CommonDict.AttributeDict],
            FlextResult[t.Ldif.CommonDict.AttributeDict],
        ],
    ) -> FlextResult[m.Ldif.Entry]:
        """Hook: Validate and CORRECT RFC syntax issues before writing Entry - static helper."""
        attrs_dict_raw = entry.attributes.attributes if entry.attributes else {}
        attrs_dict: t.Ldif.CommonDict.AttributeDict = dict(
            attrs_dict_raw.items(),
        )
        aci_validation_error = FlextLdifServersOudEntry.validate_aci_macros_in_entry(
            attrs_dict,
            validate_aci_macros,
        )
        if aci_validation_error:
            return FlextResult[m.Ldif.Entry].fail(aci_validation_error)

        return FlextLdifServersOudEntry.correct_syntax_and_return_entry(
            entry,
            attrs_dict,
            correct_rfc_syntax_in_attributes,
        )

    @staticmethod
    def validate_aci_macros_in_entry(
        attrs_dict: t.Ldif.CommonDict.AttributeDict,
        validate_aci_macros: Callable[[str], FlextResult[bool]],
    ) -> str | None:
        """Validate ACI macros if present."""
        aci_attrs = attrs_dict.get("aci")
        if aci_attrs and isinstance(aci_attrs, (list, tuple)):
            for aci_value in aci_attrs:
                if isinstance(aci_value, str):
                    validation_result = validate_aci_macros(aci_value)
                    if validation_result.is_failure:
                        return f"ACI macro validation failed: {validation_result.error}"
        return None

    @staticmethod
    def correct_syntax_and_return_entry(
        entry: m.Ldif.Entry,
        attrs_dict: t.Ldif.CommonDict.AttributeDict,
        correct_rfc_syntax_in_attributes: Callable[
            [t.Ldif.CommonDict.AttributeDict],
            FlextResult[t.Ldif.CommonDict.AttributeDict],
        ],
    ) -> FlextResult[m.Ldif.Entry]:
        """Correct RFC syntax issues and return entry."""
        corrected_result = correct_rfc_syntax_in_attributes(attrs_dict)
        if corrected_result.is_failure:
            return FlextResult[m.Ldif.Entry].fail(
                corrected_result.error or "Unknown error",
            )

        corrected_data = corrected_result.value

        corrected_data_typed: dict[
            str,
            str | int | float | bool | list[str] | dict[str, str | list[str]] | None,
        ] = dict(corrected_data)

        syntax_corrections_raw = corrected_data_typed.get("syntax_corrections")
        syntax_corrections_typed: list[str] | dict[str, str] | None = None
        if isinstance(syntax_corrections_raw, list):
            syntax_corrections_typed = [str(v) for v in syntax_corrections_raw]
        elif isinstance(syntax_corrections_raw, dict):
            syntax_corrections_dict: dict[str, str] = {}

            if isinstance(syntax_corrections_raw, dict):
                for k, v in syntax_corrections_raw.items():
                    syntax_corrections_dict[str(k)] = str(v) if v is not None else ""
            syntax_corrections_typed = syntax_corrections_dict

        if syntax_corrections_typed is not None:
            return FlextLdifServersOudEntry.apply_syntax_corrections(
                entry,
                corrected_data_typed,
                syntax_corrections_typed,
            )

        return FlextResult[m.Ldif.Entry].ok(entry)

    @staticmethod
    def apply_syntax_corrections(
        entry: m.Ldif.Entry,
        corrected_data: dict[
            str,
            str | int | float | bool | list[str] | dict[str, str | list[str]] | None,
        ],
        syntax_corrections: list[str] | dict[str, str] | None,
    ) -> FlextResult[m.Ldif.Entry]:
        """Apply syntax corrections to entry."""
        corrected_attrs_raw = corrected_data.get("corrected_attributes")

        if not isinstance(corrected_attrs_raw, dict):
            return FlextResult[m.Ldif.Entry].ok(entry)

        attrs_for_model: dict[str, list[str]] = {}
        for raw_key, raw_value in corrected_attrs_raw.items():
            if not isinstance(raw_key, str):
                continue

            if isinstance(raw_value, list):
                attrs_for_model[raw_key] = [str(item) for item in raw_value]
            elif isinstance(raw_value, str):
                attrs_for_model[raw_key] = [raw_value]
            else:
                attrs_for_model[raw_key] = [str(raw_value)]

        corrected_ldif_attrs = m.Ldif.Attributes(
            attributes=attrs_for_model,
        )
        corrected_entry = entry.model_copy(
            update={"attributes": corrected_ldif_attrs},
        )

        logger.debug(
            "OUD quirks: Applied syntax corrections before writing (structure preserved)",
            entry_dn=entry.dn.value if entry.dn else None,
            corrections_count=len(syntax_corrections)
            if isinstance(syntax_corrections, (list, tuple))
            else 0,
            corrections=syntax_corrections,
            corrected_attributes=list(attrs_for_model.keys()),
        )
        return FlextResult[m.Ldif.Entry].ok(corrected_entry)

    def _hook_finalize_entry_parse(
        self,
        entry: m.Ldif.Entry,
        original_dn: str,
        original_attrs: t.Ldif.CommonDict.AttributeDictGeneric,
    ) -> FlextResult[m.Ldif.Entry]:
        """Hook: Process ACLs and propagate their extensions to entry metadata."""
        _ = original_dn

        aci_values = self._find_aci_values(entry, original_attrs)
        if not aci_values:
            return FlextResult.ok(entry)

        if not entry.metadata:
            entry.metadata = m.Ldif.QuirkMetadata.create_for(
                "oud",
                extensions=FlextLdifModelsMetadata.DynamicMetadata(),
            )

        current_extensions: dict[str, t.MetadataAttributeValue] = (
            dict(entry.metadata.extensions) if entry.metadata.extensions else {}
        )

        parent = self._get_parent_quirk_safe()
        if parent is None:
            return FlextResult.ok(entry)

        acl_quirk_raw = getattr(parent, "_acl_quirk", None)
        if not acl_quirk_raw:
            return FlextResult.ok(entry)

        if not isinstance(acl_quirk_raw, FlextLdifServersOudAcl):
            return FlextResult.ok(entry)
        acl_quirk: FlextLdifServersOudAcl = acl_quirk_raw

        self._process_aci_list_for_finalize(aci_values, acl_quirk, current_extensions)

        if current_extensions:
            existing_extensions = (
                dict(entry.metadata.extensions)
                if entry.metadata and entry.metadata.extensions
                else {}
            )

            merged_extensions = {**existing_extensions, **current_extensions}

            entry.metadata = entry.metadata.model_copy(
                update={
                    "extensions": FlextLdifModelsMetadata.DynamicMetadata.from_dict(
                        merged_extensions,
                    ),
                },
            )

        return FlextResult.ok(entry)

    def _hook_pre_write_entry(
        self,
        entry: m.Ldif.Entry,
    ) -> FlextResult[m.Ldif.Entry]:
        """Hook: Pre-write entry validation (simplified)."""
        return FlextResult[m.Ldif.Entry].ok(entry)

    def _finalize_and_parse_entry(
        self,
        entry_dict: dict[str, t.GeneralValueType],
        entries_list: list[m.Ldif.Entry],
    ) -> None:
        """Finalize entry dict and parse into entries list."""
        if "dn" not in entry_dict:
            return

        dn = str(entry_dict.pop("dn"))
        original_entry_dict = dict(entry_dict)

        entry_attrs: dict[str, list[str]] = {}
        for k, v in entry_dict.items():
            if isinstance(v, list):
                entry_attrs[str(k)] = [
                    item.decode("utf-8") if isinstance(item, bytes) else str(item)
                    for item in v
                ]
            elif isinstance(v, bytes):
                entry_attrs[str(k)] = [v.decode("utf-8")]
            elif isinstance(v, str):
                entry_attrs[str(k)] = [v]
            else:
                entry_attrs[str(k)] = [str(v)]

        result = self.parse_entry(dn, entry_attrs)
        if result.is_success:
            entry = result.value
            original_dn = dn
            parsed_dn = entry.dn.value if entry.dn else None
            parsed_attrs = entry.attributes.attributes if entry.attributes else {}

            converted_attrs: dict[str, list[str | bytes]] = {
                k: list(v) if isinstance(v, list) else [str(v)]
                for k, v in parsed_attrs.items()
            }
            dn_differences, attribute_differences, original_attrs_complete, _ = (
                u.Ldif.Entry.analyze_differences(
                    entry_attrs=original_entry_dict,
                    converted_attrs=converted_attrs,
                    original_dn=original_dn,
                    cleaned_dn=parsed_dn or original_dn,
                )
            )

            if not entry.metadata:
                entry.metadata = m.Ldif.QuirkMetadata.create_for(
                    "oud",
                    extensions=FlextLdifModelsMetadata.DynamicMetadata(),
                )

            FlextLdifUtilitiesMetadata.store_minimal_differences(
                metadata=entry.metadata,
                dn_differences=json.dumps(dn_differences),
                attribute_differences=json.dumps(attribute_differences),
                original_dn=original_dn or "",
                parsed_dn=parsed_dn or "",
                original_attributes_complete=json.dumps(original_attrs_complete),
            )

            logger.debug(
                "OUD entry parsed with minimal differences",
                entry_dn=original_dn[:50] if original_dn else None,
            )

            entries_list.append(entry)

    def _determine_attribute_order(
        self,
        attr_names: list[str],
        format_options: m.Ldif.WriteFormatOptions | None,
    ) -> list[str]:
        """Determine attribute order based on format options."""
        if format_options and format_options.sort_attributes:
            return sorted(attr_names, key=str.lower)
        return attr_names

    def _add_attribute_transformation_comments(
        self,
        comment_lines: list[str],
        attr_name: str,
        _transformation: FlextLdifModelsDomains.AttributeTransformation,
        comment_type: str,
    ) -> None:
        """Add comment for attribute transformation."""
        comment_lines.append(
            f"# [{comment_type}] {attr_name}: transformation applied",
        )

    def _add_rejection_reason_comments(
        self,
        comment_lines: list[str],
        entry: m.Ldif.Entry,
    ) -> None:
        """Add comments with rejection reason if entry was rejected."""
        if (
            entry.metadata
            and entry.metadata.extensions
            and isinstance(entry.metadata.extensions, dict)
        ):
            rejection_reason = entry.metadata.extensions.get("rejection_reason")
            if rejection_reason:
                comment_lines.append(f"# [REJECTION] {rejection_reason}")
