"""Extracted nested class from FlextLdifUtilities.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_cli import u

from flext_ldif._utilities import FlextLdifEntryAccess
from flext_ldif._utilities import FlextLdifEntryAnalysis
from flext_ldif._utilities import FlextLdifEntryAttributeValidation
from flext_ldif._utilities import FlextLdifEntryBooleanConversion
from flext_ldif._utilities import FlextLdifEntryCriteria
from flext_ldif._utilities import FlextLdifEntryMatching
from flext_ldif._utilities import FlextLdifEntryOidRfcTransforming
from flext_ldif._utilities import FlextLdifEntryServerRules
from flext_ldif._utilities import FlextLdifEntryValidation


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
