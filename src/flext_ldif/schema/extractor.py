"""Schema extractor module for LDIF processing."""

from __future__ import annotations

from typing import cast, override

from flext_core import FlextResult, FlextService

from flext_ldif.config import FlextLdifConfig
from flext_ldif.models import FlextLdifModels
from flext_ldif.typings import FlextLdifTypes


class FlextLdifSchemaExtractor(FlextService["FlextLdifConfig"]):
    """Schema extraction service for LDIF entries."""

    @override
    def __init__(self) -> None:
        """Initialize schema extractor."""
        super().__init__()

    @override
    def execute(self) -> FlextResult[FlextLdifConfig]:
        """Execute schema extractor service."""
        return FlextResult[FlextLdifConfig].fail(
            "Use extract_from_entries() method instead"
        )

    def extract_from_entries(
        self, entries: list[FlextLdifModels.Entry]
    ) -> FlextResult[FlextLdifModels.SchemaDiscoveryResult]:
        """Extract schema from LDIF entries.

        Args:
            entries: List of LDIF entries to analyze

        Returns:
            FlextResult containing discovered schema

        """
        if not entries:
            return FlextResult[FlextLdifModels.SchemaDiscoveryResult].fail(
                "No entries provided for schema extraction"
            )

        try:
            attributes: dict[str, dict[str, str]] = {}
            object_classes: dict[str, dict[str, str]] = {}

            for entry in entries:
                for attr_name, attr_values in entry.attributes.data.items():
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
                            "single_value": str(len(attr_values) <= 1),
                        }

            result = FlextLdifModels.SchemaDiscoveryResult(
                attributes=attributes,
                objectclasses=object_classes,
                total_attributes=len(attributes),
                total_objectclasses=len(object_classes),
            )

            if self.logger:
                self.logger.info(
                    f"Extracted schema: {len(attributes)} attributes, "
                    f"{len(object_classes)} objectClasses from {len(entries)} entries"
                )

            return FlextResult[FlextLdifModels.SchemaDiscoveryResult].ok(result)

        except Exception as e:
            return FlextResult[FlextLdifModels.SchemaDiscoveryResult].fail(
                f"Schema extraction failed: {e}"
            )

    def extract_attribute_usage(
        self, entries: list[FlextLdifModels.Entry]
    ) -> FlextResult[FlextLdifTypes.NestedDict]:
        """Extract attribute usage statistics from entries.

        Args:
            entries: List of LDIF entries to analyze

        Returns:
            FlextResult containing attribute usage statistics

        """
        if not entries:
            return FlextResult[FlextLdifTypes.NestedDict].ok({})

        usage_stats: FlextLdifTypes.NestedDict = {}

        for entry in entries:
            for attr_name, attr_values in entry.attributes.data.items():
                if attr_name not in usage_stats:
                    usage_stats[attr_name] = {
                        "count": 0,
                        "max_values": 0,
                        "single_valued": True,
                    }

                stats = usage_stats[attr_name]
                stats["count"] = cast("int", stats["count"]) + 1

                value_count = len(attr_values)
                if value_count > cast("int", stats["max_values"]):
                    stats["max_values"] = value_count

                if value_count > 1:
                    stats["single_valued"] = False

        return FlextResult[FlextLdifTypes.NestedDict].ok(usage_stats)


__all__ = ["FlextLdifSchemaExtractor"]
