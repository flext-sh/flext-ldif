"""Configuration management for LDIF operations using Pydantic models with validation.

This module manages all configuration aspects for flext-ldif package including
parsing, writing, server detection, and validation settings. Provides
comprehensive LDIF processing configuration with server-specific servers
handling, format options for parsing and writing, and advanced validation rules.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from typing import Annotated, ClassVar

from pydantic import BaseModel, Field
from pydantic_settings import SettingsConfigDict

from flext_cli import FlextCliSettings


class FlextLdifSettings(FlextCliSettings):
    """LDIF processing settings inheriting base FLEXT configuration."""

    class LdifSettings(BaseModel):
        """Namespaced LDIF runtime settings."""

        ldif_encoding: Annotated[
            str,
            Field(description="Default encoding for LDIF read/write operations"),
        ] = "utf-8"
        ldif_strict_validation: Annotated[
            bool,
            Field(description="Enable strict LDIF validation rules"),
        ] = True

    model_config: ClassVar[SettingsConfigDict] = SettingsConfigDict(
        env_prefix="FLEXT_LDIF_",
        extra="ignore",
    )

    Ldif: LdifSettings = Field(
        default_factory=LdifSettings,
        description="Namespaced LDIF settings branch.",
    )


settings: FlextLdifSettings = FlextLdifSettings.fetch_global()
"""Pre-instantiated project settings singleton — ``from flext_ldif import settings``."""

__all__: list[str] = ["FlextLdifSettings", "settings"]
