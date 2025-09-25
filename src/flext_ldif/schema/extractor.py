"""FLEXT LDIF Schema Extractor.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from typing import cast

from flext_core import FlextLogger, FlextResult, FlextService
from flext_ldif.models import FlextLdifModels


class FlextLdifSchemaExtractor(FlextService[FlextLdifModels.SchemaDiscoveryResult]):
    """Schema extraction service for LDIF entries."""

    def __init__(self) -> None:
        """Initialize schema extractor."""
        super().__init__()
        self._logger = FlextLogger(__name__)

    def execute(self: object) -> FlextResult[FlextLdifModels.SchemaDiscoveryResult]:
        """Execute schema extractor service."""
        return FlextResult[FlextLdifModels.SchemaDiscoveryResult].fail(
            "Use extract_from_entries() method instead"
        )

    async def execute_async(
        self: object,
    ) -> FlextResult[FlextLdifModels.SchemaDiscoveryResult]:
        """Execute schema extractor service asynchronously."""
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
            discovered_dns: list[str] = []

            for entry in entries:
                discovered_dns.append(entry.dn.value)

                for attr_name, attr_values in entry.attributes.data.items():
                    if attr_name not in attributes:
                        attr_result = FlextLdifModels.SchemaAttribute.create(
                            name=attr_name,
                            oid=f"1.3.6.1.4.1.{hash(attr_name) % 1000000}",  # Generate OID
                            description="Discovered from LDIF entries",
                            single_value=len(attr_values) <= 1,
                        )
                        if attr_result.is_success:
                            attributes[attr_name] = attr_result.value

                    if attr_name.lower() == "objectclass":
                        for oc_name in attr_values:
                            if oc_name not in object_classes:
                                oc_result = FlextLdifModels.SchemaObjectClass.create(
                                    name=oc_name,
                                    description="Discovered from LDIF entries",
                                )
                                if oc_result.is_success:
                                    object_classes[oc_name] = cast("FlextLdifModels.SchemaObjectClass", oc_result.value)

            result = FlextLdifModels.SchemaDiscoveryResult.create(
                object_classes=object_classes,
                attributes=attributes,
                entry_count=len(entries),
                discovered_dns=list(set(discovered_dns)),
            )

            if result.is_success:
                self._logger.info(
                    f"Extracted schema: {len(attributes)} attributes, "
                    f"{len(object_classes)} objectClasses from {len(entries)} entries"
                )

            return result

        except Exception as e:
            return FlextResult[FlextLdifModels.SchemaDiscoveryResult].fail(
                f"Schema extraction failed: {e}"
            )

    def extract_attribute_usage(
        self, entries: list[FlextLdifModels.Entry]
    ) -> FlextResult[dict[str, dict[str, object]]]:
        """Extract attribute usage statistics from entries.

        Args:
            entries: List of LDIF entries to analyze

        Returns:
            FlextResult containing attribute usage statistics

        """
        if not entries:
            return FlextResult[dict[str, dict[str, object]]].ok({})

        usage_stats: dict[str, dict[str, object]] = {}

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

        return FlextResult[dict[str, dict[str, object]]].ok(usage_stats)


__all__ = ["FlextLdifSchemaExtractor"]
