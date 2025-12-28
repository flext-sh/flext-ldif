"""Oracle Unified Directory (OUD) Utilities.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

Provides OUD-specific utility functions for ACL parsing configuration.
"""

from __future__ import annotations

from flext_ldif._models.settings import FlextLdifModelsSettings
from flext_ldif.servers._oud.constants import FlextLdifServersOudConstants


class FlextLdifServersOudUtilities:
    """Oracle Unified Directory-specific utilities.

    Provides factory methods and helpers for OUD server operations.
    Moved from constants.py to comply with architecture rules
    (constants.py must contain only constants).
    """

    @staticmethod
    def get_parser_config() -> FlextLdifModelsSettings.AciParserConfig:
        """Create AciParserConfig for OUD ACL parsing.

        Returns:
            AciParserConfig with OUD-specific patterns from Constants.

        """
        constants = FlextLdifServersOudConstants
        return FlextLdifModelsSettings.AciParserConfig(
            server_type="oud",  # Use literal string for ServerTypeLiteral compatibility
            aci_prefix="aci:",
            version_acl_pattern=constants.ACL_VERSION_ACL_PATTERN,
            targetattr_pattern=constants.ACL_TARGETATTR_PATTERN,
            allow_deny_pattern=constants.ACL_ALLOW_DENY_PATTERN,
            bind_patterns=dict(constants.ACL_BIND_PATTERNS),
            extra_patterns={
                "targetscope": constants.ACL_TARGETSCOPE_PATTERN,
                "targattrfilters": constants.ACL_TARGATTRFILTERS_PATTERN,
                "targetcontrol": constants.ACL_TARGETCONTROL_PATTERN,
                "extop": constants.ACL_EXTOP_PATTERN,
                "ip": constants.ACL_IP_PATTERN,
                "dns": constants.ACL_DNS_PATTERN,
                "dayofweek": constants.ACL_DAYOFWEEK_PATTERN,
                "timeofday": constants.ACL_TIMEOFDAY_PATTERN,
                "authmethod": constants.ACL_AUTHMETHOD_PATTERN,
                "ssf": constants.ACL_SSF_PATTERN,
            },
        )


__all__ = ["FlextLdifServersOudUtilities"]
