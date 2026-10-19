"""LDIF settings mix-in: processing.

from flext_ldif import m
from flext_ldif import u
Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from typing import Annotated, Self

from flext_core import m

from flext_ldif._constants.base import FlextLdifConstantsEnums
from flext_ldif._models._settings_normalization import (
    FlextLdifModelsSettingsNormalization,
)
from flext_ldif._models.base import FlextLdifShared


class FlextLdifModelsSettingsProcessing:
    """LDIF settings mix-in: processing."""

    class ProcessConfig(m.Value):
        """Configuration for processing operations."""

        @staticmethod
        def _coerce_server_type_value(
            value: FlextLdifConstantsEnums.ServerTypes | str | None,
        ) -> str | None:

            if value is None:
                return None
            return FlextLdifShared.normalize_server_type(value).value

        type NormalizedServerTypeValue = Annotated[
            str | None,
            m.BeforeValidator(_coerce_server_type_value),
        ]

        batch_size: Annotated[
            int,
            m.Field(description="Number of entries to process per batch"),
        ] = 100
        timeout_seconds: Annotated[
            int,
            m.Field(description="Maximum processing time in seconds"),
        ] = 300
        max_retries: Annotated[
            int,
            m.Field(description="Maximum retry attempts on failure"),
        ] = 3
        source_server: Annotated[
            NormalizedServerTypeValue,
            m.Field(description="Source LDAP server type identifier"),
        ] = None
        target_server: Annotated[
            NormalizedServerTypeValue,
            m.Field(description="Target LDAP server type identifier"),
        ] = None
        base_dn: Annotated[
            str,
            m.Field(description="Migration base DN for OID→OUD ACL scope filtering"),
        ] = ""
        dn_config: Annotated[
            FlextLdifModelsSettingsNormalization.DnNormalizationConfig | None,
            m.Field(description="DN normalization configuration"),
        ] = None
        attr_config: Annotated[
            FlextLdifModelsSettingsNormalization.AttrNormalizationConfig | None,
            m.Field(description="Attribute normalization configuration"),
        ] = None

        @classmethod
        def servers(
            cls,
            *,
            source_server: str | FlextLdifConstantsEnums.ServerTypes | None,
            target_server: str | FlextLdifConstantsEnums.ServerTypes | None,
            base_dn: str = "",
        ) -> Self:
            """Build processing config keeping model defaults untouched.

            Returns:
                The resulting ``Self``.

            """
            return cls(
                source_server=source_server,
                target_server=target_server,
                base_dn=base_dn,
            )

    class TransformConfig(m.Value):
        """Configuration for transformation operations."""

        fail_fast: Annotated[
            bool,
            m.Field(description="Stop on first transformation error"),
        ] = False
        preserve_order: Annotated[
            bool,
            m.Field(description="Preserve original entry ordering"),
        ] = True
        track_changes: Annotated[
            bool,
            m.Field(description="Track attribute-level changes for audit"),
        ] = False
        normalize_dns: Annotated[
            bool,
            m.Field(description="Normalize DNs during transformation"),
        ] = False
        normalize_attrs: Annotated[
            bool,
            m.Field(description="Normalize attributes during transformation"),
        ] = False
        process_config: Annotated[
            FlextLdifModelsSettingsProcessing.ProcessConfig | None,
            m.Field(description="Processing configuration for batch operations"),
        ] = None

        @classmethod
        def servers(
            cls,
            *,
            source_server: str | FlextLdifConstantsEnums.ServerTypes | None,
            target_server: str | FlextLdifConstantsEnums.ServerTypes | None,
            base_dn: str = "",
        ) -> Self:
            """Build transform config for server-to-server conversion only.

            Returns:
                The resulting ``Self``.

            """
            return cls(
                normalize_dns=True,
                normalize_attrs=True,
                process_config=FlextLdifModelsSettingsProcessing.ProcessConfig.servers(
                    source_server=source_server,
                    target_server=target_server,
                    base_dn=base_dn,
                ),
            )


__all__: list[str] = ["FlextLdifModelsSettingsProcessing"]
