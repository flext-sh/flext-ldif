"""Shared utilities for flext-ldif domain.

This module provides shared utility functions that can be imported by
both models and utilities modules without creating circular dependencies.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import cast

from flext_ldif.constants import c


def normalize_server_type(server_type: str) -> c.Ldif.LiteralTypes.ServerTypeLiteral:
    """Normalize server type string to canonical ServerTypes enum value.

    Converts aliases and variations to canonical short form:
    - "active_directory", "ad", "ActiveDirectory" → "ad"
    - "oracle_oid", "oid", "OID" → "oid"
    - etc.

    Returns canonical ServerTypes enum value (short identifier).
    Raises ValueError if server_type is not recognized.

    Note: Return value is guaranteed to be a valid ServerTypeLiteral string,
    but returned as `str` for type compatibility. All returned values are
    validated against ServerTypes enum members.
    """
    server_type_lower = server_type.lower().strip()
    # Map aliases to canonical forms
    # Use full path to ServerTypes to avoid name resolution issues
    alias_map: dict[str, str] = {
        "active_directory": c.Ldif.ServerTypes.AD.value,
        "activedirectory": c.Ldif.ServerTypes.AD.value,
        "oracle_oid": c.Ldif.ServerTypes.OID.value,
        "oracleoid": c.Ldif.ServerTypes.OID.value,
        "oracle_oud": c.Ldif.ServerTypes.OUD.value,
        "oracleoud": c.Ldif.ServerTypes.OUD.value,
        "openldap": c.Ldif.ServerTypes.OPENLDAP2.value,  # "openldap" maps to "openldap2"
        "openldap1": c.Ldif.ServerTypes.OPENLDAP1.value,
        "openldap2": c.Ldif.ServerTypes.OPENLDAP2.value,
        "ibm_tivoli": c.Ldif.ServerTypes.IBM_TIVOLI.value,
        "ibmtivoli": c.Ldif.ServerTypes.IBM_TIVOLI.value,
        "tivoli": c.Ldif.ServerTypes.IBM_TIVOLI.value,
    }
    # Check alias map first
    if server_type_lower in alias_map:
        # alias_map values are guaranteed valid ServerTypeLiterals
        return cast(
            "c.Ldif.LiteralTypes.ServerTypeLiteral",
            alias_map[server_type_lower],
        )
    # Check if it's already a canonical value
    # ServerTypes is a StrEnum, iterate over enum members
    for server_enum in c.Ldif.ServerTypes.__members__.values():
        if server_enum.value == server_type_lower:
            # Return the enum member's value which is already a ServerTypeLiteral
            return server_enum.value
    # Not found
    # ServerTypes is a StrEnum, iterate over enum members
    valid_types = [s.value for s in c.Ldif.ServerTypes.__members__.values()]
    msg = f"Invalid server type: {server_type}. Valid types: {valid_types}"
    raise ValueError(msg)
