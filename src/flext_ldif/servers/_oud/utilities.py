"""Oracle Unified Directory (OUD) Utilities."""

from __future__ import annotations

from flext_ldif._models.settings import FlextLdifModelsSettings
from flext_ldif.servers._oud.constants import FlextLdifServersOudConstants


class FlextLdifServersOudUtilities:
    """Oracle Unified Directory-specific utilities."""

    @staticmethod
    def get_parser_config() -> FlextLdifModelsSettings.AciParserConfig:
        """Create AciParserConfig for OUD ACL parsing."""
        constants = FlextLdifServersOudConstants
        return FlextLdifModelsSettings.AciParserConfig(
            server_type="oud",
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
