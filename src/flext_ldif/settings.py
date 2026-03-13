"""Configuration management for LDIF operations using Pydantic models with validation.

This module manages all configuration aspects for flext-ldif package including
parsing, writing, server detection, and validation settings. Provides
comprehensive LDIF processing configuration with server-specific quirks
handling, format options for parsing and writing, and advanced validation rules.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from typing import Annotated

from flext_core import FlextSettings
from pydantic import Field


class FlextLdifSettings(FlextSettings):
    """LDIF processing settings inheriting base FLEXT configuration."""

    ldif_encoding: Annotated[
        str,
        Field(
            default="utf-8",
            description="Default encoding for LDIF read/write operations",
        ),
    ]
    ldif_strict_validation: Annotated[
        bool, Field(default=True, description="Enable strict LDIF validation rules")
    ]


__all__ = ["FlextLdifSettings"]
