"""LDIF settings mix-in: acl.

from flext_ldif import m
from flext_ldif import u
Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from typing import Annotated

from flext_core import m, t

from flext_ldif._constants.base import (
    FlextLdifConstantsAclConvertOud,
    FlextLdifConstantsEnums,
)


class FlextLdifModelsSettingsAcl:
    """LDIF settings mix-in: acl."""

    class AciLineFormatConfig(m.Value):
        """Configuration for formatting a complete ACI line from components."""

        name: Annotated[str, m.Field(..., description="ACL name")]
        target_clause: Annotated[
            str,
            m.Field(..., description="Target clause (e.g., '(targetattr=\"cn\")')"),
        ]
        permissions_clause: Annotated[
            str,
            m.Field(..., description="Permissions clause (e.g., 'allow (read,write)')"),
        ]
        bind_rule: Annotated[
            str,
            m.Field(..., description="Bind rule (e.g., 'userdn=\"ldap:///self\"')"),
        ]
        aci_prefix: Annotated[str, m.Field(description="ACI attribute prefix")] = (
            "aci: "
        )
        version: Annotated[str, m.Field(description="ACI version")] = (
            FlextLdifConstantsAclConvertOud.ACI_VERSION_NUMBER
        )

    class AciParserConfig(m.Value):
        """Configuration for server-specific ACI parsing."""

        server_type: Annotated[
            FlextLdifConstantsEnums.ServerTypes,
            m.Field(..., description="Server type identifier (oid, oud, rfc, etc.)"),
        ]
        aci_prefix: Annotated[str, m.Field(description="ACI line prefix")] = "aci:"
        version_acl_pattern: Annotated[
            str,
            m.Field(description="Regex pattern to extract version and ACL name"),
        ] = r'\(version\s+(\d+\.\d+)\s*;\s*acl\s+"([^"]+)"'
        targetattr_pattern: Annotated[
            str,
            m.Field(description="Regex pattern to extract target attributes"),
        ] = r'(\(targetattr\s*=\s*"([^"]*)")'
        default_targetattr: Annotated[
            str,
            m.Field(description="Default targetattr when none found"),
        ] = "*"
        allow_deny_pattern: Annotated[
            str,
            m.Field(description="Regex pattern to extract allow/deny permissions"),
        ] = r"(allow|deny)\s*\(([^)]*)\)"
        ops_separator: Annotated[
            str,
            m.Field(description="Separator for operations list"),
        ] = ","
        action_filter: Annotated[
            str | None,
            m.Field(description="Only include permissions for this action"),
        ] = None
        bind_patterns: Annotated[
            t.MutableStrMapping,
            m.Field(description="Mapping of bind type names to regex patterns"),
        ] = m.Field(default_factory=dict)
        permission_map: Annotated[
            t.MutableStrMapping,
            m.Field(description="Permission name normalization map"),
        ] = m.Field(default_factory=dict)
        special_subjects: Annotated[
            t.MutableStrPairMapping,
            m.Field(description="Special subject value mappings"),
        ] = m.Field(default_factory=dict)
        extra_patterns: Annotated[
            t.MutableStrMapping,
            m.Field(description="Additional extraction patterns for extensions"),
        ] = m.Field(default_factory=dict)
        default_name: Annotated[
            str,
            m.Field(description="Default ACL name when none found"),
        ] = "unnamed-acl"

    class AclMetadataConfig(m.Value):
        """Configuration for building ACL metadata extensions."""

        line_breaks: Annotated[
            t.JsonValueList | None,
            m.Field(description="Line break positions"),
        ] = None
        dn_spaces: Annotated[
            str | None,
            m.Field(description="DN spacing information"),
        ] = None
        targetscope: Annotated[
            t.JsonValueList | None,
            m.Field(description="Target scope values"),
        ] = None
        version: Annotated[str | None, m.Field(description="ACI version string")] = None
        action_type: Annotated[
            str | None,
            m.Field(description="Action type (allow/deny)"),
        ] = None


__all__: list[str] = ["FlextLdifModelsSettingsAcl"]
