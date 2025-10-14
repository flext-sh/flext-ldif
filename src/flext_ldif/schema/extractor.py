"""Schema extractor module for LDIF processing."""

from __future__ import annotations

from typing import override

from flext_core import FlextCore

from flext_ldif.config import FlextLdifConfig
from flext_ldif.models import FlextLdifModels
from flext_ldif.typings import FlextLdifTypes


class FlextLdifSchemaExtractor(FlextCore.Service["FlextLdifConfig"]):
    """Schema extraction service for LDIF entries."""

    @override
    def __init__(self) -> None:
        """Initialize schema extractor."""
        super().__init__()

    @override
    def execute(self) -> FlextCore.Result[FlextLdifConfig]:
        """Execute schema extractor service."""
        return FlextCore.Result[FlextLdifConfig].fail(
            "Use extract_from_entries() method instead"
        )

    def extract_from_entries(
        self, entries: list[FlextLdifModels.Entry]
    ) -> FlextCore.Result[FlextLdifModels.SchemaDiscoveryResult]:
        """Extract schema from LDIF entries.

        Args:
            entries: List of LDIF entries to analyze

        Returns:
            FlextCore.Result containing discovered schema

        """
        if not entries:
            return FlextCore.Result[FlextLdifModels.SchemaDiscoveryResult].fail(
                "No entries provided for schema extraction"
            )

        try:
            attributes: dict[str, dict[str, str]] = {}
            object_classes: dict[str, dict[str, str]] = {}

            for entry in entries:
                for attr_name, attr_values in entry.attributes.attributes.items():
                    if attr_name.lower() == "objectclass":
                        # Handle object classes specially
                        for oc_name in attr_values:
                            if oc_name not in object_classes:
                                object_classes[str(oc_name)] = {
                                    "name": str(oc_name),
                                    "oid": f"1.3.6.1.4.1.{hash(oc_name) % 1000000}",
                                    "description": f"Auto-discovered object class {oc_name}",
                                }
                    # Handle regular attributes
                    elif attr_name not in attributes:
                        attributes[attr_name] = {
                            "name": attr_name,
                            "oid": f"1.3.6.1.4.1.{hash(attr_name) % 1000000}",
                            "description": "Discovered from LDIF entries",
                            "syntax": "1.3.6.1.4.1.1466.115.121.1.15",  # Directory String
                            "single_value": str(len(attr_values.values) <= 1),
                        }

            # Cast to match SchemaDiscoveryResult type expectations
            # Type narrowing: dict[str, dict[str, str]] -> dict[str, FlextCore.Types.Dict]
            attributes_obj: dict[str, FlextCore.Types.Dict] = {
                k: dict(v.items()) for k, v in attributes.items()
            }
            object_classes_obj: dict[str, FlextCore.Types.Dict] = {
                k: dict(v.items()) for k, v in object_classes.items()
            }

            result = FlextLdifModels.SchemaDiscoveryResult(
                attributes=attributes_obj,
                objectclasses=object_classes_obj,
                total_attributes=len(attributes),
                total_objectclasses=len(object_classes),
            )

            if self.logger:
                self.logger.info(
                    f"Extracted schema: {len(attributes)} attributes, "
                    f"{len(object_classes)} objectClasses from {len(entries)} entries"
                )

            return FlextCore.Result[FlextLdifModels.SchemaDiscoveryResult].ok(result)

        except Exception as e:
            return FlextCore.Result[FlextLdifModels.SchemaDiscoveryResult].fail(
                f"Schema extraction failed: {e}"
            )

    def extract_attribute_usage(
        self, entries: list[FlextLdifModels.Entry]
    ) -> FlextCore.Result[FlextLdifTypes.NestedDict]:
        """Extract attribute usage statistics from entries.

        Args:
            entries: List of LDIF entries to analyze

        Returns:
            FlextCore.Result containing attribute usage statistics

        """
        if not entries:
            return FlextCore.Result[FlextLdifTypes.NestedDict].ok({})

        usage_stats: FlextLdifTypes.NestedDict = {}

        for entry in entries:
            for attr_name, attr_values in entry.attributes.attributes.items():
                if attr_name not in usage_stats:
                    usage_stats[attr_name] = {
                        "count": 0,
                        "max_values": 0,
                        "single_valued": True,
                    }

                stats = usage_stats[attr_name]

                # Type narrow count to int before incrementing
                count_raw = stats["count"]
                if not isinstance(count_raw, int):
                    count_raw = 0  # Default to 0 if not int
                stats["count"] = count_raw + 1

                value_count = len(attr_values.values)

                # Type narrow max_values to int before comparison
                max_values_raw = stats["max_values"]
                if not isinstance(max_values_raw, int):
                    max_values_raw = 0  # Default to 0 if not int

                if value_count > max_values_raw:
                    stats["max_values"] = value_count

                if value_count > 1:
                    stats["single_valued"] = False

        return FlextCore.Result[FlextLdifTypes.NestedDict].ok(usage_stats)


__all__ = ["FlextLdifSchemaExtractor"]
