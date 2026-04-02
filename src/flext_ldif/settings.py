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

from pydantic import Field

from flext_core import FlextSettings


class FlextLdifSettings(FlextSettings):
    """LDIF processing settings inheriting base FLEXT configuration."""

    ldif_encoding: Annotated[
        str,
        Field(description="Default encoding for LDIF read/write operations"),
    ] = "utf-8"
    ldif_strict_validation: Annotated[
        bool,
        Field(description="Enable strict LDIF validation rules"),
    ] = True


__all__ = ["FlextLdifSettings"]
