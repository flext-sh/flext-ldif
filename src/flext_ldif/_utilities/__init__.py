"""Extracted nested classes from FlextLdifUtilities for better modularity.

This module contains nested classes that were extracted from FlextLdifUtilities
to separate files while maintaining 100% backward compatibility through aliases.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from flext_ldif._utilities.acl import FlextLdifUtilitiesACL
from flext_ldif._utilities.dn import FlextLdifUtilitiesDN
from flext_ldif._utilities.entry import FlextLdifUtilitiesEntry
from flext_ldif._utilities.object_class import FlextLdifUtilitiesObjectClass
from flext_ldif._utilities.oid import FlextLdifUtilitiesOID
from flext_ldif._utilities.parser import FlextLdifUtilitiesParser
from flext_ldif._utilities.schema import FlextLdifUtilitiesSchema
from flext_ldif._utilities.writer import FlextLdifUtilitiesWriter

__all__ = [
    "FlextLdifUtilitiesACL",
    "FlextLdifUtilitiesDN",
    "FlextLdifUtilitiesEntry",
    "FlextLdifUtilitiesOID",
    "FlextLdifUtilitiesObjectClass",
    "FlextLdifUtilitiesParser",
    "FlextLdifUtilitiesSchema",
    "FlextLdifUtilitiesWriter",
]
