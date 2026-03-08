"""Configuration management for LDIF operations using Pydantic models with validation.

This module manages all configuration aspects for flext-ldif package including
parsing, writing, server detection, and validation settings. Provides
comprehensive LDIF processing configuration with server-specific quirks
handling, format options for parsing and writing, and advanced validation rules.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

# =========================================================================
# PUBLIC API - Direct access to models (no wrappers)
# =========================================================================
# XS|    # Use FlextLdifSettings fields (ldif_write_*) for formatting options


# BJ|    # Direct access via FlextLdifModelsSettings.WriteFormatOptions when needed
# Direct access via FlextLdifModelsSettings.WriteFormatOptions when needed


__all__ = ["FlextLdifSettings"]
