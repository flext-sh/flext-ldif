"""LDIF metadata JSON normalization core utilities.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Mapping

from flext_cli import u

from flext_ldif import FlextLdifModels, c, p, t


class FlextLdifMetadataJsonCore:
    """Canonical JSON/metadata normalization primitives."""

    @staticmethod
    def dump_json_payload(value: t.JsonPayload | None) -> str:
        """Serialize any CLI JSON-compatible payload through the canonical DSL.

        Returns:
            The resulting ``str``.
        """
        if value is None:
            return ""
        payload_json: str = FlextLdifModels.Cli.CliNormalizedJson(
            t.Cli.JSON_VALUE_ADAPTER.validate_python(u.to_jsonable_python(value)),
        ).model_dump_json()
        return payload_json

    @staticmethod
    def dump_dynamic_metadata(value: t.Ldif.MetadataInputMapping | None) -> str:
        """Serialize metadata-shaped mappings to a canonical JSON string.

        Returns:
            The resulting ``str``.
        """
        if not value:
            return ""
        dumped: str = FlextLdifMetadataJsonCore.dump_json_payload(dict(value))
        return dumped

    @staticmethod
    def _add_to_dict_metadata(
        metadata: t.Ldif.MutableMetadataMapping,
        metadata_key: str,
        item_data: t.JsonValue,
    ) -> None:
        """Add item to dict metadata."""
        value = metadata.get(metadata_key)
        if isinstance(value, Mapping) and isinstance(item_data, Mapping):
            merged_value = dict(
                t.Cli.JSON_MAPPING_ADAPTER.validate_python({
                    inner_key: u.normalize_to_metadata(inner_value)
                    for inner_key, inner_value in value.items()
                }),
            )
            for write_option_key, inner_value in item_data.items():
                merged_value[write_option_key] = u.normalize_to_metadata(inner_value)
            metadata[metadata_key] = merged_value
            return
        metadata[metadata_key] = u.normalize_to_metadata(item_data)

    @staticmethod
    def _get_metadata_dict(
        model: p.Ldif.ModelWithValidationMetadata,
    ) -> t.Ldif.MutableMetadataMapping:
        """Get mutable metadata dict from model.

        Returns:
            The resulting ``t.Ldif.MutableMetadataMapping``.
        """
        metadata_obj = getattr(model, "validation_metadata", None)
        if metadata_obj is None:
            metadata_obj = FlextLdifModels.Metadata(attributes={})
        if isinstance(metadata_obj, FlextLdifModels.Metadata):
            return {
                key: u.normalize_to_metadata(value)
                for key, value in metadata_obj.attributes.items()
            }
        return {}

    @staticmethod
    def _is_metadata_scalar(value: t.JsonPayload | None) -> bool:
        return value is None or isinstance(value, c.PRIMITIVES_TYPES)

    @staticmethod
    def _normalize_dict_list(
        values: t.SequenceOf[t.JsonValue],
    ) -> t.MutableSequenceOf[t.JsonValue]:

        normalized: t.MutableSequenceOf[t.JsonValue] = []
        for item in values:
            normalized.append(u.normalize_to_metadata(item))
        return normalized

    @staticmethod
    def _update_conversion_path(
        metadata: t.Ldif.MutableMetadataMapping,
        update_conversion_path: str,
    ) -> None:
        """Update conversion_path in metadata."""
        if "conversion_path" not in metadata:
            metadata["conversion_path"] = update_conversion_path
        else:
            current_path_obj = metadata["conversion_path"]
            if (
                isinstance(current_path_obj, str)
                and update_conversion_path not in current_path_obj
            ):
                metadata["conversion_path"] = (
                    f"{current_path_obj}->{update_conversion_path}"
                )


__all__: list[str] = ["FlextLdifMetadataJsonCore"]
