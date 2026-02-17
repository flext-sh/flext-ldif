"""Shared utilities for flext-ldif domain.

This module provides shared utility functions that can be imported by
both models and utilities modules without creating circular dependencies.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_ldif.constants import c


def normalize_server_type(server_type: str) -> c.Ldif.ServerTypes:
    """Normalize server type string to canonical ServerTypes enum member.

    Converts aliases and variations to canonical enum member:
    - "active_directory", "ad", "ActiveDirectory" → ServerTypes.AD
    - "oracle_oid", "oid", "OID" → ServerTypes.OID
    - etc.

    Returns canonical ServerTypes enum member. Since ServerTypes is a StrEnum,
    the returned value can be used directly as a string in comparisons.
    Raises ValueError if server_type is not recognized.
    """
    server_type_lower = server_type.lower().strip()
    # Map aliases to canonical enum members
    alias_map: dict[str, c.Ldif.ServerTypes] = {
        "active_directory": c.Ldif.ServerTypes.AD,
        "activedirectory": c.Ldif.ServerTypes.AD,
        "oracle_oid": c.Ldif.ServerTypes.OID,
        "oracleoid": c.Ldif.ServerTypes.OID,
        "oracle_oud": c.Ldif.ServerTypes.OUD,
        "oracleoud": c.Ldif.ServerTypes.OUD,
        "openldap": c.Ldif.ServerTypes.OPENLDAP2,  # "openldap" maps to OPENLDAP2
        "openldap1": c.Ldif.ServerTypes.OPENLDAP1,
        "openldap2": c.Ldif.ServerTypes.OPENLDAP2,
        "ibm_tivoli": c.Ldif.ServerTypes.IBM_TIVOLI,
        "ibmtivoli": c.Ldif.ServerTypes.IBM_TIVOLI,
        "tivoli": c.Ldif.ServerTypes.IBM_TIVOLI,
        "novell_edirectory": c.Ldif.ServerTypes.NOVELL,
        "novelledirectory": c.Ldif.ServerTypes.NOVELL,
        "edirectory": c.Ldif.ServerTypes.NOVELL,
        "apache_directory": c.Ldif.ServerTypes.APACHE,
        "apachedirectory": c.Ldif.ServerTypes.APACHE,
        "apacheds": c.Ldif.ServerTypes.APACHE,
        "389ds": c.Ldif.ServerTypes.DS389,
        "389directory": c.Ldif.ServerTypes.DS389,
    }
    # Check alias map first
    if server_type_lower in alias_map:
        return alias_map[server_type_lower]
    # Check if it's already a canonical value
    for server_enum in c.Ldif.ServerTypes.__members__.values():
        if server_enum.value == server_type_lower:
            return server_enum
    # Not found
    valid_types = [s.value for s in c.Ldif.ServerTypes.__members__.values()]
    msg = f"Invalid server type: {server_type}. Valid types: {valid_types}"
    raise ValueError(msg)
