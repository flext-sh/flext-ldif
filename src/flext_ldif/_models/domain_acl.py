"""ACL domain models — permissions, targets, subjects, and write metadata.

from flext_ldif import m
from flext_ldif import u
Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import Annotated, Self

from flext_core import FlextUtilities as u, m
from flext_ldif import c, t
from flext_ldif._models.base import FlextLdifModelsBases as mb
from flext_ldif._models.domain_metadata import FlextLdifModelsDomainMetadata


class FlextLdifModelsDomainAcl:
    """Namespace for LDIF ACL domain models."""

    class AclPermissions(m.ArbitraryTypesModel):
        """ACL permissions for LDAP operations.

        Supports:
        - Standard RFC permissions (read, write, add, delete, search, compare)
        - Server-specific permissions (self_write, proxy, browse, auth)
        - Negative permissions (no_write, no_add, no_delete, no_browse, no_self_write)
        - Compound permissions (all)
        """

        read: Annotated[bool, u.Field(description="Read permission")] = False
        write: Annotated[bool, u.Field(description="Write permission")] = False
        add: Annotated[bool, u.Field(description="Add permission")] = False
        delete: Annotated[bool, u.Field(description="Delete permission")] = False
        search: Annotated[bool, u.Field(description="Search permission")] = False
        compare: Annotated[bool, u.Field(description="Compare permission")] = False
        self_write: Annotated[
            bool, u.Field(description="Self-write permission (OID, OUD)")
        ] = False
        proxy: Annotated[
            bool, u.Field(description="Proxy permission (OID, OUD, 389DS)")
        ] = False
        browse: Annotated[
            bool, u.Field(description="Browse permission (OID) - maps to read+search")
        ] = False
        auth: Annotated[
            bool, u.Field(description="Auth permission (OID) - authentication access")
        ] = False
        all: Annotated[
            bool, u.Field(description="All permissions (compound permission)")
        ] = False
        no_write: Annotated[
            bool, u.Field(description="Deny write permission (OID)")
        ] = False
        no_add: Annotated[bool, u.Field(description="Deny add permission (OID)")] = (
            False
        )
        no_delete: Annotated[
            bool, u.Field(description="Deny delete permission (OID)")
        ] = False
        no_browse: Annotated[
            bool, u.Field(description="Deny browse permission (OID)")
        ] = False
        no_self_write: Annotated[
            bool, u.Field(description="Deny self-write permission (OID)")
        ] = False

        @staticmethod
        def filter_rfc_compliant_permissions(
            perms_dict: t.MutableBoolMapping,
        ) -> t.MutableBoolMapping:
            """Filter permissions dict to RFC-compliant fields only.

            Architecture: Server-specific permissions (like OID's "none") are excluded
            from this model and stored in metadata instead. This method ensures
            AclPermissions only contains RFC-compliant or widely-supported permissions.

            Args:
                perms_dict: Dictionary with permission name → bool (from parser)

            Returns:
                Filtered dict containing only RFC-compliant permission keys

            """
            rfc_compliant_keys = {
                "read",
                "write",
                "add",
                "delete",
                "search",
                "compare",
                "self_write",
                "proxy",
                "browse",
                "auth",
                "all",
                "no_write",
                "no_add",
                "no_delete",
                "no_browse",
                "no_self_write",
            }
            return {
                key: value
                for key, value in perms_dict.items()
                if key in rfc_compliant_keys
            }

    class AclTarget(m.ArbitraryTypesModel):
        """ACL target specification."""

        target_dn: Annotated[str, u.Field(..., description="Target DN pattern")]
        attributes: Annotated[
            t.MutableSequenceOf[str], u.Field(description="Target attributes")
        ]

    class AclSubject(m.ArbitraryTypesModel):
        """ACL subject specification."""

        subject_type: Annotated[
            c.Ldif.AclSubjectType,
            u.Field(..., description="Subject type (user, group, etc.)"),
        ]
        subject_value: Annotated[str, u.Field(..., description="Subject value/pattern")]

    class Acl(mb.AclElement):
        """Universal ACL model for all LDAP server types.

        Inherits from mb.AclElement:
        - model_config (strict=True, validate_default=True, validate_assignment=True)
        - server_type field with default "rfc"
        - metadata field (ServerMetadata | None)
        - validation_violations field (list[str])
        - is_valid computed field
        - has_server_servers computed field
        """

        name: Annotated[str, u.Field(description="ACL name")] = ""
        target: Annotated[
            FlextLdifModelsDomainAcl.AclTarget | None,
            u.Field(description="ACL target specification"),
        ] = None
        subject: Annotated[
            FlextLdifModelsDomainAcl.AclSubject | None,
            u.Field(description="ACL subject specification"),
        ] = None
        permissions: Annotated[
            FlextLdifModelsDomainAcl.AclPermissions | None,
            u.Field(description="ACL permission flags"),
        ] = None
        raw_line: Annotated[
            str, u.Field(description="Original raw ACL line from LDIF")
        ] = ""
        raw_acl: Annotated[
            str, u.Field(description="Original ACL string from LDIF")
        ] = ""
        metadata: Annotated[
            FlextLdifModelsDomainMetadata.ServerMetadata | None,
            u.Field(description="Server-specific metadata for ACL processing"),
        ] = None

        @classmethod
        def resolve_acl_format(cls) -> str:
            """Get ACL format for this server type.

            Business Rule: This method doesn't use instance state, only class constants.
            Implication: Can be a class method for better clarity and allows override in subclasses.

            Returns:
                Default ACL format string from constants.

            """
            default_acl_format: str = c.Ldif.DEFAULT_ACL_FORMAT
            return default_acl_format

        def resolve_acl_type(self) -> str:
            """Get ACL type identifier for this server using canonical enum normalization."""
            server_type_raw = str(self.server_type).lower().strip()
            aliased_server_type = c.Ldif.SERVER_TYPE_ALIASES.get(server_type_raw)
            canonical_server_type = (
                aliased_server_type.value
                if aliased_server_type is not None
                else server_type_raw
            )
            return f"{canonical_server_type}_acl"

        @u.model_validator(mode="after")
        def validate_acl_format(self) -> Self:
            """Validate ACL format - capture violations in metadata, DON'T reject.

            IMPORTANT: Pydantic 2 requires model validators with mode="after" to return
            `self` (not a copy) when validating via __init__. We modify self in-place
            using attribute assignment helpers.

            See: https://docs.pydantic.dev/latest/concepts/validators/#model-validators
            """
            violations: t.MutableSequenceOf[str] = []
            valid_server_types: frozenset[c.Ldif.ServerTypes] = frozenset({
                c.Ldif.ServerTypes.RFC,
                c.Ldif.ServerTypes.OPENLDAP,
                c.Ldif.ServerTypes.OPENLDAP2,
                c.Ldif.ServerTypes.OPENLDAP1,
                c.Ldif.ServerTypes.OID,
                c.Ldif.ServerTypes.OUD,
                c.Ldif.ServerTypes.DS389,
                c.Ldif.ServerTypes.AD,
                c.Ldif.ServerTypes.RELAXED,
            })
            server_type_raw = str(self.server_type).lower().strip()
            aliased_server_type = c.Ldif.SERVER_TYPE_ALIASES.get(server_type_raw)
            canonical_server_type = (
                aliased_server_type.value
                if aliased_server_type is not None
                else server_type_raw
            )
            valid_server_type_values = frozenset(
                server_type.value for server_type in valid_server_types
            )
            if canonical_server_type not in valid_server_type_values:
                violations.append(
                    "Invalid server_type "
                    f"'{self.server_type}' - expected one of: "
                    f"{', '.join(sorted(valid_server_type_values))}"
                )
            acl_is_defined = (
                self.target is not None
                or self.subject is not None
                or self.permissions is not None
            )
            if acl_is_defined and not (self.raw_acl and self.raw_acl.strip()):
                violations.append(
                    "ACL is defined (has target/subject/permissions) but raw_acl is empty"
                )
            if violations:
                self.validation_violations.clear()
                self.validation_violations.extend(violations)
            return self

    class AclWriteMetadata(m.FrozenModel):
        """Metadata for ACL write formatting operations.

        This frozen model encapsulates ACL metadata extracted from ServerMetadata.extensions
        for use in ACL formatting during LDIF writing operations.

        Used by Entry servers to format ACI attributes with original ACL format names,
        following SRP by separating ACL formatting from Writer serialization.

        Attributes:
            original_format: Original ACL string format (always preserve for conversion).
            source_server: Server that parsed this ACL (oid, oud, openldap, etc.).
            name_sanitized: True if ACL name was sanitized (had control chars).
            original_name_raw: Original ACL name before sanitization (for audit).

        Example:
            >>> metadata = AclWriteMetadata.from_extensions(entry.metadata.extensions)
            >>> if metadata.original_format:
            ...     sanitized = FlextLdifUtilities.ACL.sanitize_acl_name(
            ...         metadata.original_format
            ...     )

        """

        original_format: Annotated[
            str | None,
            u.Field(description="Original ACL string format from source server"),
        ] = None
        source_server: Annotated[
            str | None, u.Field(description="Server type that parsed this ACL")
        ] = None
        name_sanitized: Annotated[
            bool,
            u.Field(description="True if ACL name was sanitized during processing"),
        ] = False
        original_name_raw: Annotated[
            str | None, u.Field(description="Original ACL name before sanitization")
        ] = None

        @classmethod
        def from_extensions(
            cls, extensions: t.Ldif.MetadataInputMapping | None
        ) -> Self:
            """Extract ACL write metadata from ServerMetadata extensions.

            Factory method to create AclWriteMetadata from the extensions dict
            stored in ServerMetadata.extensions, using MetadataKeys constants.

            Args:
                extensions: ServerMetadata.extensions dict containing ACL metadata.
                    Expected keys: ACL_ORIGINAL_FORMAT, ACL_SOURCE_SERVER,
                    ACL_NAME_SANITIZED, ACL_ORIGINAL_NAME_RAW.

            Returns:
                AclWriteMetadata instance with extracted values.

            Example:
                >>> extensions = {"original_format": "orclaci: access to entry..."}
                >>> metadata = AclWriteMetadata.from_extensions(extensions)
                >>> metadata.original_format
                'orclaci: access to entry...'

            """
            if not extensions:
                validated: Self = cls.model_validate({
                    "original_format": None,
                    "source_server": None,
                    "name_sanitized": False,
                    "original_name_raw": None,
                })
                return validated
            keys = c.Ldif
            original_format = extensions.get(keys.ACL_ORIGINAL_FORMAT)
            source_server = extensions.get(keys.ACL_SOURCE_SERVER)
            name_sanitized = extensions.get(keys.ACL_NAME_SANITIZED, False)
            original_name_raw = extensions.get(keys.ACL_ORIGINAL_NAME_RAW)
            return cls(
                original_format=str(original_format) if original_format else None,
                source_server=str(source_server) if source_server else None,
                name_sanitized=bool(name_sanitized),
                original_name_raw=str(original_name_raw) if original_name_raw else None,
            )

        def has_original_format(self) -> bool:
            """Check if original ACL format is available for name replacement."""
            return self.original_format is not None and bool(self.original_format)


__all__: list[str] = ["FlextLdifModelsDomainAcl"]
