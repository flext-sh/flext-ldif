"""Schema extractor module for LDIF processing."""

from __future__ import annotations

from typing import cast, override

from flext_core import FlextLogger, FlextResult, FlextService, FlextTypes

from flext_ldif.models import FlextLdifModels


class FlextLdifSchemaExtractor(FlextService[FlextLdifModels.SchemaDiscoveryResult]):
    """Schema extraction service for LDIF entries."""

    @override
    def __init__(self) -> None:
        """Initialize schema extractor."""
        super().__init__()
        self._logger = FlextLogger(__name__)

    @override
    def execute(self: object) -> FlextResult[FlextLdifModels.SchemaDiscoveryResult]:
        """Execute schema extractor service."""
        return FlextResult[FlextLdifModels.SchemaDiscoveryResult].fail(
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
            attributes: dict[str, FlextLdifModels.SchemaAttribute] = {}
            object_classes: dict[str, FlextLdifModels.SchemaObjectClass] = {}

            for entry in entries:
                for attr_name, attr_values in entry.attributes.data.items():
                    if attr_name.lower() == "objectclass":
                        # Handle object classes specially
                        for oc_name in attr_values.values:
                            if oc_name not in object_classes:
                                oc_result = FlextLdifModels.SchemaObjectClass.create(
                                    name=oc_name,
                                    oid=f"1.3.6.1.4.1.{hash(oc_name) % 1000000}",
                                )
                                if oc_result.is_success and isinstance(
                                    oc_result.value, FlextLdifModels.SchemaObjectClass
                                ):
                                    object_classes[str(oc_name)] = oc_result.value
                    # Handle regular attributes
                    elif attr_name not in attributes:
                        attr_result = FlextLdifModels.SchemaAttribute.create(
                            name=attr_name,
                            oid=f"1.3.6.1.4.1.{hash(attr_name) % 1000000}",
                            description="Discovered from LDIF entries",
                            single_value=len(attr_values.values) <= 1,
                        )
                        if attr_result.is_success and isinstance(
                            attr_result.value, FlextLdifModels.SchemaAttribute
                        ):
                            attributes[attr_name] = attr_result.value

            result = FlextLdifModels.SchemaDiscoveryResult.create(
                object_classes=object_classes,
                attributes=attributes,
            )

            if result.is_success:
                self._logger.info(
                    f"Extracted schema: {len(attributes)} attributes, "
                    f"{len(object_classes)} objectClasses from {len(entries)} entries"
                )

            if result.is_success and isinstance(
                result.value, FlextLdifModels.SchemaDiscoveryResult
            ):
                return FlextResult[FlextLdifModels.SchemaDiscoveryResult].ok(
                    result.value
                )
            return FlextResult[FlextLdifModels.SchemaDiscoveryResult].fail(
                result.error or "Failed to create schema"
            )

        except Exception as e:
            return FlextResult[FlextLdifModels.SchemaDiscoveryResult].fail(
                f"Schema extraction failed: {e}"
            )

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
