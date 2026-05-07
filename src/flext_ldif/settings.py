"""Configuration management for LDIF operations using Pydantic models with validation.

This module manages all configuration aspects for flext-ldif package including
parsing, writing, server detection, and validation settings. Provides
comprehensive LDIF processing configuration with server-specific servers
handling, format options for parsing and writing, and advanced validation rules.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from typing import TYPE_CHECKING, Annotated, ClassVar

from flext_cli import FlextCliSettings
from flext_ldif import c, m, u

if TYPE_CHECKING:
    from flext_ldif import p


class FlextLdifSettings(FlextCliSettings):
    """LDIF processing settings inheriting base FLEXT configuration."""

    class LdifSettings(m.Value):
        """Namespaced LDIF runtime settings."""

        ldif_encoding: Annotated[
            c.Ldif.Encoding | str,
            u.Field(description="Default encoding for LDIF read/write operations"),
        ] = c.Ldif.Encoding.UTF8
        ldif_strict_validation: Annotated[
            bool,
            u.Field(description="Enable strict LDIF validation rules"),
        ] = c.Ldif.DEFAULT_STRICT_VALIDATION

    model_config: ClassVar[m.SettingsConfigDict] = m.SettingsConfigDict(
        env_prefix="FLEXT_LDIF_",
        extra="ignore",
    )

    if TYPE_CHECKING:
        Ldif: p.Ldif.LdifSettings
    else:
        Ldif: LdifSettings = m.Field(
            default_factory=LdifSettings,
            description="Namespaced LDIF settings branch.",
        )


__all__: list[str] = ["FlextLdifSettings"]
