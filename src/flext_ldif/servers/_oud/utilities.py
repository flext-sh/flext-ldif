"""Oracle Unified Directory (OUD) Utilities."""

from __future__ import annotations

from flext_ldif import c, m, t
from flext_ldif.servers._oud.constants import FlextLdifServersOudConstants


class FlextLdifServersOudUtilities:
    """Oracle Unified Directory-specific utilities."""

    @staticmethod
    def get_parser_config() -> m.Ldif.AciParserConfig:
        """Create AciParserConfig for OUD ACL parsing."""
        constants = FlextLdifServersOudConstants
        config: m.Ldif.AciParserConfig = m.Ldif.AciParserConfig.model_validate({
            "server_type": c.Ldif.ServerTypes.OUD,
            "aci_prefix": "aci:",
            "version_acl_pattern": constants.ACL_VERSION_ACL_PATTERN,
            "targetattr_pattern": constants.ACL_TARGETATTR_PATTERN,
            "allow_deny_pattern": constants.ACL_ALLOW_DENY_PATTERN,
            "bind_patterns": t.str_dict_adapter().validate_python(
                constants.ACL_BIND_PATTERNS
            ),
            "permission_map": {},
            "special_subjects": {},
            "extra_patterns": {
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
        })
        return config


__all__: list[str] = ["FlextLdifServersOudUtilities"]

u = FlextLdifServersOudUtilities
