"""LDIF settings mix-in: acl.

from flext_ldif import m
from flext_ldif import u
Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from typing import TYPE_CHECKING, Annotated

from flext_core import FlextUtilities as u, m

if TYPE_CHECKING:
    from flext_ldif import c, t
    from flext_ldif._models.domain_acl import FlextLdifModelsDomainAcl as mdac


class FlextLdifModelsSettingsAcl:
    """LDIF settings mix-in: acl."""

    class AciLineFormatConfig(m.Value):
        """Configuration for formatting a complete ACI line from components."""

        name: Annotated[str, u.Field(..., description="ACL name")]
        target_clause: Annotated[
            str, u.Field(..., description="Target clause (e.g., '(targetattr=\"cn\")')")
        ]
        permissions_clause: Annotated[
            str,
            u.Field(..., description="Permissions clause (e.g., 'allow (read,write)')"),
        ]
        bind_rule: Annotated[
            str, u.Field(..., description="Bind rule (e.g., 'userdn=\"ldap:///self\"')")
        ]
        aci_prefix: Annotated[str, u.Field(description="ACI attribute prefix")] = (
            "aci: "
        )
        version: Annotated[str, u.Field(description="ACI version")] = "3.0"

    class AciParserConfig(m.Value):
        """Configuration for server-specific ACI parsing."""

        server_type: Annotated[
            c.Ldif.ServerTypes,
            u.Field(..., description="Server type identifier (oid, oud, rfc, etc.)"),
        ]
        aci_prefix: Annotated[str, u.Field(description="ACI line prefix")] = "aci:"
        version_acl_pattern: Annotated[
            str, u.Field(description="Regex pattern to extract version and ACL name")
        ] = r'\(version\s+(\d+\.\d+)\s*;\s*acl\s+"([^"]+)"'
        targetattr_pattern: Annotated[
            str, u.Field(description="Regex pattern to extract target attributes")
        ] = r'(\(targetattr\s*=\s*"([^"]*)")'
        default_targetattr: Annotated[
            str, u.Field(description="Default targetattr when none found")
        ] = "*"
        allow_deny_pattern: Annotated[
            str, u.Field(description="Regex pattern to extract allow/deny permissions")
        ] = r"(allow|deny)\s*\(([^)]*)\)"
        ops_separator: Annotated[
            str, u.Field(description="Separator for operations list")
        ] = ","
        action_filter: Annotated[
            str | None, u.Field(description="Only include permissions for this action")
        ] = None
        bind_patterns: Annotated[
            t.MutableStrMapping,
            u.Field(description="Mapping of bind type names to regex patterns"),
        ] = u.Field(default_factory=dict)
        permission_map: Annotated[
            t.MutableStrMapping,
            u.Field(description="Permission name normalization map"),
        ] = u.Field(default_factory=dict)
        special_subjects: Annotated[
            t.MutableStrPairMapping,
            u.Field(description="Special subject value mappings"),
        ] = u.Field(default_factory=dict)
        extra_patterns: Annotated[
            t.MutableStrMapping,
            u.Field(description="Additional extraction patterns for extensions"),
        ] = u.Field(default_factory=dict)
        default_name: Annotated[
            str, u.Field(description="Default ACL name when none found")
        ] = "unnamed-acl"

    class AclMetadataConfig(m.Value):
        """Configuration for building ACL metadata extensions."""

        line_breaks: Annotated[
            t.JsonValueList | None, u.Field(description="Line break positions")
        ] = None
        dn_spaces: Annotated[
            str | None, u.Field(description="DN spacing information")
        ] = None
        targetscope: Annotated[
            t.JsonValueList | None, u.Field(description="Target scope values")
        ] = None
        version: Annotated[str | None, u.Field(description="ACI version string")] = None
        action_type: Annotated[
            str | None, u.Field(description="Action type (allow/deny)")
        ] = None

    class PermissionMappingConfig(m.Value):
        """Configuration for permission mapping during ACL conversion.

        Consolidates parameters for
        FlextLdifConversion._apply_permission_mapping method.
        Reduces function signature from 6 parameters to 1 model.

        """

        original_acl: Annotated[mdac.Acl, u.Field(description="Original ACL model")]
        converted_acl: Annotated[
            mdac.Acl, u.Field(description="Converted ACL model (modified in-place)")
        ]
        orig_perms_dict: Annotated[
            t.MutableBoolMapping, u.Field(..., description="Original permissions dict")
        ]
        source_server_type: Annotated[
            c.Ldif.ServerTypes | None, u.Field(description="Source server type")
        ] = None
        target_server_type: Annotated[
            c.Ldif.ServerTypes | None, u.Field(description="Target server type")
        ] = None
        converted_has_permissions: Annotated[
            bool, u.Field(description="Whether converted ACL has permissions")
        ] = False
