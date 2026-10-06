"""LDIF boolean-conversion tracking metadata utilities.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import ClassVar

from flext_cli import u

from flext_ldif import FlextLdifModels, p, t


class FlextLdifMetadataTracking:
    """Track boolean conversions for round-trip delta support."""

    _module_logger: ClassVar[p.Logger] = u.fetch_logger(__name__)

    @staticmethod
    def track_boolean_conversion(
        metadata: FlextLdifModels.Ldif.ServerMetadata,
        attr_name: str,
        original_value: str,
        converted_value: str,
        format_direction: str = "OID->RFC",
    ) -> None:
        """Track boolean conversion for round-trip support."""
        if format_direction == "OID->RFC":
            source_key = f"{attr_name}:oid_value"
            target_key = f"{attr_name}:rfc_value"
        else:
            source_key = f"{attr_name}:rfc_value"
            target_key = f"{attr_name}:oid_value"
        metadata.boolean_conversions[source_key] = original_value
        metadata.boolean_conversions[target_key] = converted_value
        FlextLdifMetadataTracking._module_logger.debug(
            "Boolean conversion tracked",
            attr_name=attr_name,
            format_direction=format_direction,
        )

    @staticmethod
    def store_minimal_differences(
        metadata: FlextLdifModels.Ldif.ServerMetadata,
        **extra: t.Ldif.Scalar,
    ) -> None:
        """Store minimal differences in metadata for delta tracking."""
        _ = metadata
        _ = extra


__all__: list[str] = ["FlextLdifMetadataTracking"]
