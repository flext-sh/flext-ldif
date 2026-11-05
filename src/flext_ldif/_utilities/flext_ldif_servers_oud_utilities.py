"""Flext ldif servers oud utilities module.

Copyright (c) 2026 FLEXT Team. All rights reserved.
src/flext_ldif/_utilities/flext_ldif_servers_oud_utilities
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_ldif.constants import c
from flext_ldif.models import m
from flext_ldif.protocols import p


class FlextLdifUtilitiesServersOud:
    """Oracle Unified Directory-specific utilities."""

    @staticmethod
    def resolve_parser_config() -> p.Ldif.AciParserConfig:
        """Create AciParserConfig for OUD ACL parsing.

        Returns:
            The resulting ``m.Ldif.AciParserConfig``.

        """
        config: p.Ldif.AciParserConfig = m.Ldif.AciParserConfig.model_validate({
            "server_type": c.Ldif.ServerTypes.OUD,
            "aci_prefix": "aci:",
            "version_acl_pattern": c.Ldif.ACL_VERSION_ACL_PATTERN,
            "targetattr_pattern": c.Ldif.ACL_TARGETATTR_PATTERN,
            "allow_deny_pattern": c.Ldif.ACL_ALLOW_DENY_PATTERN,
            "bind_patterns": c.Ldif.ACL_BIND_PATTERNS,
            "permission_map": dict(c.Ldif.ACL_PERMISSION_TOKEN_MAP),
            "special_subjects": {},
            "extra_patterns": {
                "targetscope": c.Ldif.ACL_TARGETSCOPE_PATTERN,
                "targattrfilters": c.Ldif.ACL_TARGATTRFILTERS_PATTERN,
                "targetcontrol": c.Ldif.ACL_TARGETCONTROL_PATTERN,
                "extop": c.Ldif.ACL_EXTOP_PATTERN,
                "ip": c.Ldif.ACL_IP_PATTERN,
                "dns": c.Ldif.ACL_DNS_PATTERN,
                "dayofweek": c.Ldif.ACL_DAYOFWEEK_PATTERN,
                "timeofday": c.Ldif.ACL_TIMEOFDAY_PATTERN,
                "authmethod": c.Ldif.ACL_AUTHMETHOD_PATTERN,
                "ssf": c.Ldif.ACL_SSF_PATTERN,
            },
        })
        return config


__all__: list[str] = ["FlextLdifUtilitiesServersOud"]
