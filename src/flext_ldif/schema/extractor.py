"""Schema extractor module for LDIF processing."""

from __future__ import annotations

from typing import TYPE_CHECKING, cast, override

from flext_core import FlextLogger, FlextResult, FlextService, FlextTypes

if TYPE_CHECKING:
    from flext_ldif.models import FlextLdifModels


class FlextLdifSchemaExtractor(FlextService):
    """Schema extraction service for LDIF entries."""

    @override
    def __init__(self) -> None:
        """Initialize schema extractor."""
        super().__init__()
        self._logger = FlextLogger(__name__)

    @override
    def execute(self: object) -> FlextResult[FlextTypes.Dict]:
        """Execute schema extractor service."""
        return FlextResult[FlextTypes.Dict].fail(
            "Use extract_from_entries() method instead"
        )

    def extract_from_entries(
        self, entries: list[FlextLdifModels.Entry]
    ) -> FlextResult[FlextTypes.Dict]:
        """Extract schema from LDIF entries.

        Args:
            entries: List of LDIF entries to analyze

        Returns:
            FlextResult containing discovered schema

        """
        if not entries:
            return FlextResult["FlextLdifModels.SchemaDiscoveryResult"].fail(
                "No entries provided for schema extraction"
            )

        try:
            attributes: dict[str, dict[str, str]] = {}
            object_classes: dict[str, dict[str, str]] = {}

            for entry in entries:
                for attr_name, attr_values in entry.attributes.data.items():
                    if attr_name.lower() == "objectclass":
                        # Handle object classes specially
                        for oc_name in attr_values.values:
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

            schema_data = {
                "object_classes": object_classes,
                "attributes": attributes,
            }

            self._logger.info(
                f"Extracted schema: {len(attributes)} attributes, "
                f"{len(object_classes)} objectClasses from {len(entries)} entries"
            )

            # Return as FlextResult with dict data - models will be created by caller
            return FlextResult[FlextTypes.Dict].ok(schema_data)

        except Exception as e:
            return FlextResult[FlextTypes.Dict].fail(f"Schema extraction failed: {e}")

    def extract_attribute_usage(
        self, entries: list[FlextLdifModels.Entry]
    ) -> FlextResult[FlextTypes.NestedDict]:
        """Extract attribute usage statistics from entries.

        Args:
            entries: List of LDIF entries to analyze

        Returns:
            FlextResult containing attribute usage statistics

        """
        if not entries:
            return FlextResult[FlextTypes.NestedDict].ok({})

        usage_stats: FlextTypes.NestedDict = {}

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

                value_count = len(attr_values.values)
                if value_count > cast("int", stats["max_values"]):
                    stats["max_values"] = value_count

                if value_count > 1:
                    stats["single_valued"] = False

        return FlextResult[FlextTypes.NestedDict].ok(usage_stats)


__all__ = ["FlextLdifSchemaExtractor"]
