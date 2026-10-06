"""Extracted nested class from FlextLdifUtilities.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_cli import u

from flext_ldif._utilities._entry_access import FlextLdifEntryAccess
from flext_ldif._utilities._entry_analysis import FlextLdifEntryAnalysis
from flext_ldif._utilities._entry_attr_validation import (
    FlextLdifEntryAttributeValidation,
)
from flext_ldif._utilities._entry_boolean import FlextLdifEntryBooleanConversion
from flext_ldif._utilities._entry_criteria import FlextLdifEntryCriteria
from flext_ldif._utilities._entry_matching import FlextLdifEntryMatching
from flext_ldif._utilities._entry_oid_rfc import FlextLdifEntryOidRfcTransforming
from flext_ldif._utilities._entry_server_rules import FlextLdifEntryServerRules
from flext_ldif._utilities._entry_validation import FlextLdifEntryValidation


class FlextLdifUtilitiesEntry(
    FlextLdifEntryAccess,
    FlextLdifEntryValidation,
    FlextLdifEntryAttributeValidation,
    FlextLdifEntryServerRules,
    FlextLdifEntryOidRfcTransforming,
    FlextLdifEntryBooleanConversion,
    FlextLdifEntryAnalysis,
    FlextLdifEntryMatching,
    FlextLdifEntryCriteria,
):
    """Entry transformation utilities - pure helper functions."""

    logger = u.fetch_logger(__name__)


__all__: list[str] = ["FlextLdifUtilitiesEntry"]
