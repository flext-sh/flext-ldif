"""LDAP Server Type Constants.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from typing import Final

SERVER_TYPE_OPENLDAP: Final[str] = "openldap"
SERVER_TYPE_389DS: Final[str] = "389ds"
SERVER_TYPE_ORACLE_OID: Final[str] = "oracle_oid"
SERVER_TYPE_ORACLE_OUD: Final[str] = "oracle_oud"
SERVER_TYPE_ACTIVE_DIRECTORY: Final[str] = "active_directory"
SERVER_TYPE_GENERIC: Final[str] = "generic"

SUPPORTED_SERVER_TYPES: Final[list[str]] = [
    SERVER_TYPE_OPENLDAP,
    SERVER_TYPE_389DS,
    SERVER_TYPE_ORACLE_OID,
    SERVER_TYPE_ORACLE_OUD,
    SERVER_TYPE_ACTIVE_DIRECTORY,
    SERVER_TYPE_GENERIC,
]

__all__ = [
    "SERVER_TYPE_389DS",
    "SERVER_TYPE_ACTIVE_DIRECTORY",
    "SERVER_TYPE_GENERIC",
    "SERVER_TYPE_OPENLDAP",
    "SERVER_TYPE_ORACLE_OID",
    "SERVER_TYPE_ORACLE_OUD",
    "SUPPORTED_SERVER_TYPES",
]
