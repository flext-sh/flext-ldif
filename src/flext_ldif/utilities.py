"""Utility classes for LDIF processing pipeline.

DEPRECATED: Use services instead (FlextLdifDnService, FlextLdifStatisticsService).

This module provides thin wrapper classes that delegate to service implementations.
Scheduled for removal in v0.11.0. Use services directly:
 - FlextLdifDnService: DN and attribute normalization
 - FlextLdifStatisticsService: Pipeline statistics generation

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import re
from pathlib import Path

from flext_core import FlextResult, FlextUtilities

from flext_ldif import FlextLdifModels
from flext_ldif.constants import FlextLdifConstants
from flext_ldif.services.dn import FlextLdifDnService
from flext_ldif.typings import FlextLdifTypes


class FlextLdifUtilities:
    """Unified utilities for LDIF processing pipeline.

    Provides four main utility components:
    - Normalizer: DN and attribute normalization
    - Sorter: Entry sorting and ordering
    - Statistics: Pipeline statistics generation
    - AclUtils: ACL component creation and validation

    """

    class Normalizer:
        """DN and attribute normalization utilities.

        DEPRECATED: Use FlextLdifDnService instead.

        Provides methods for normalizing DN values and DN-valued attributes
        in LDIF entries according to canonical DN mappings. These methods
        delegate to FlextLdifDnService for actual implementation.

        """

        @staticmethod
        def build_canonical_dn_map(
            categorized: dict[str, list[dict[str, object]]],
        ) -> dict[str, str]:
            """Build mapping of lowercase(cleaned DN) -> canonical cleaned DN.

            DEPRECATED: Use FlextLdifDnService.build_canonical_dn_map instead.

            Uses FlextLdifDnService.clean_dn to normalize formatting and ensures
            case-consistent canonical values based on parsed entries.

            Args:
                categorized: Dictionary mapping category to entry list

            Returns:
                Dictionary mapping lowercase cleaned DN to canonical cleaned DN

            """
            dn_service = FlextLdifDnService()
            result = dn_service.build_canonical_dn_map(categorized)
            return result.value if result.is_success else {}

        @staticmethod
        def normalize_dn_value(value: str, dn_map: dict[str, str]) -> str:
            """Normalize a single DN value using canonical map, fallback to cleaned DN.

            DEPRECATED: Use FlextLdifDnService.normalize_dn_value instead.

            Args:
                value: DN value to normalize
                dn_map: Canonical DN mapping

            Returns:
                Normalized DN value

            """
            dn_service = FlextLdifDnService()
            return dn_service.normalize_dn_value(value, dn_map)

        @staticmethod
        def normalize_dn_references_for_entry(
            entry: dict[str, object],
            dn_map: dict[str, str],
            ref_attrs_lower: set[str],
        ) -> dict[str, object]:
            """Normalize DN-valued attributes in an entry according to dn_map.

            Handles both str and list[str] attribute values.

            Args:
                entry: Entry to normalize
                dn_map: Canonical DN mapping
                ref_attrs_lower: Set of lowercase DN reference attribute names

            Returns:
                Entry with normalized DN attributes

            """
            normalized = entry.copy()
            attrs = normalized.get(FlextLdifConstants.DictKeys.ATTRIBUTES, {})
            if not isinstance(attrs, dict):
                return normalized

            new_attrs: dict[str, object] = {}
            for attr_name, attr_value in attrs.items():
                if attr_name.lower() in ref_attrs_lower:
                    if isinstance(attr_value, list):
                        new_attrs[attr_name] = [
                            (
                                FlextLdifUtilities.Normalizer.normalize_dn_value(
                                    v, dn_map
                                )
                                if isinstance(v, str)
                                else v
                            )
                            for v in attr_value
                        ]
                    elif isinstance(attr_value, str):
                        new_attrs[attr_name] = (
                            FlextLdifUtilities.Normalizer.normalize_dn_value(
                                attr_value, dn_map
                            )
                        )
                    else:
                        new_attrs[attr_name] = attr_value
                else:
                    new_attrs[attr_name] = attr_value

            normalized[FlextLdifConstants.DictKeys.ATTRIBUTES] = new_attrs
            return normalized

        @staticmethod
        def normalize_aci_dn_references(
            entry: dict[str, object], dn_map: dict[str, str]
        ) -> dict[str, object]:
            """Normalize DNs embedded in ACI attribute strings using dn_map.

            Attempts to detect DN substrings in common OUD ACI patterns and
            replace them with canonical DNs.

            Args:
                entry: Entry with ACI attributes to normalize
                dn_map: Canonical DN mapping

            Returns:
                Entry with normalized ACI DN references

            """
            try:
                attrs = entry.get(FlextLdifConstants.DictKeys.ATTRIBUTES, {})
                if not isinstance(attrs, dict):
                    return entry

                def normalize_in_text(text: str) -> str:
                    """Normalize DNs in ACI text."""

                    def repl_ldap(m: re.Match[str]) -> str:
                        dn_part = m.group(1)
                        norm = FlextLdifUtilities.Normalizer.normalize_dn_value(
                            dn_part, dn_map
                        )
                        return f"ldap:///{norm}"

                    text2 = re.sub(r"ldap:///([^\"]+?)", repl_ldap, text)

                    # Also handle bare quoted DN-like sequences (best-effort)
                    def repl_quoted(m: re.Match[str]) -> str:
                        dn_part = m.group(1)
                        norm = FlextLdifUtilities.Normalizer.normalize_dn_value(
                            dn_part, dn_map
                        )
                        return f'"{norm}"'

                    return re.sub(
                        r'"((?:[a-zA-Z]+=[^,\";\)]+)(?:,[a-zA-Z]+=[^,\";\)]+)*)"',
                        repl_quoted,
                        text2,
                    )

                aci_value = attrs.get("aci")
                if isinstance(aci_value, list):
                    attrs["aci"] = [
                        normalize_in_text(v) if isinstance(v, str) else v
                        for v in aci_value
                    ]
                elif isinstance(aci_value, str):
                    attrs["aci"] = normalize_in_text(aci_value)

                entry_out = entry.copy()
                entry_out[FlextLdifConstants.DictKeys.ATTRIBUTES] = attrs
                return entry_out
            except (ValueError, TypeError, AttributeError, RuntimeError, Exception):
                return entry

    class Sorter:
        """Entry sorting and ordering utilities.

        Provides sorting methods for LDIF entries with hierarchy-aware ordering.

        """

        @staticmethod
        def sort_entries_by_hierarchy_and_name(
            entries: list[dict[str, object]],
        ) -> list[dict[str, object]]:
            """Sort entries by DN hierarchy depth, then case-insensitive DN.

            Ordering rules:
            - First key: DN depth (fewer RDN components first)
            - Second key: Case-insensitive DN string for stable ordering

            This ensures deterministic ordering across all categories.

            Args:
                entries: List of entries to sort

            Returns:
                Sorted entries by hierarchy and name

            """

            def sort_key(entry: dict[str, object]) -> tuple[int, str]:
                dn_value = entry.get(FlextLdifConstants.DictKeys.DN, "")
                dn = dn_value if isinstance(dn_value, str) else ""
                dn_clean = FlextLdifDnService.clean_dn(dn)
                depth = dn_clean.count(",") + (1 if dn_clean else 0)
                return (depth, dn_clean.lower())

            # Filter only entries with a DN string to avoid exceptions during sort
            sortable = [
                e
                for e in entries
                if isinstance(e.get(FlextLdifConstants.DictKeys.DN, ""), str)
            ]
            nonsortable = [
                e
                for e in entries
                if not isinstance(e.get(FlextLdifConstants.DictKeys.DN, ""), str)
            ]

            # Sort sortable entries and keep any non-sortable at the end in original order
            return sorted(sortable, key=sort_key) + nonsortable

    class Statistics:
        """Pipeline statistics generation utilities.

        Provides methods for generating comprehensive statistics about
        categorized and migrated LDIF entries.

        """

        @staticmethod
        def generate_statistics(
            categorized: dict[str, list[dict[str, object]]],
            written_counts: dict[str, int],
            output_dir: object,  # Path object
            output_files: dict[
                str, object
            ],  # category -> filename mapping (flexible type for compatibility)
        ) -> dict[str, object]:
            """Generate complete statistics for categorized migration.

            Args:
                categorized: Dictionary mapping category to entry list
                written_counts: Dictionary mapping category to count written
                output_dir: Output directory path
                output_files: Dictionary mapping category to output filename

            Returns:
                Statistics dictionary with counts, rejection info, and metadata

            """
            # Calculate total entries
            total_entries = sum(len(entries) for entries in categorized.values())

            # Build categorized counts
            categorized_counts: dict[str, object] = {}
            for category, entries in categorized.items():
                categorized_counts[category] = len(entries)

            # Count rejections and gather reasons
            rejected_entries = categorized.get("rejected", [])
            rejection_count = len(rejected_entries)
            rejection_reasons: list[str] = []

            for entry in rejected_entries:
                attrs = entry.get(FlextLdifConstants.DictKeys.ATTRIBUTES, {})
                if isinstance(attrs, dict) and "rejectionReason" in attrs:
                    reason_value = attrs["rejectionReason"]
                    if (
                        isinstance(reason_value, str)
                        and reason_value not in rejection_reasons
                    ):
                        rejection_reasons.append(reason_value)

            # Calculate rejection rate
            rejection_rate = (
                rejection_count / total_entries if total_entries > 0 else 0.0
            )

            # Build output files info (LDIF files, not directories)
            output_files_info: dict[str, object] = {}
            for category in written_counts:
                filename_obj = output_files.get(
                    category,
                    f"{category}{FlextLdifConstants.ServerDetection.LDIF_FILE_EXTENSION}",
                )
                category_filename = (
                    filename_obj
                    if isinstance(filename_obj, str)
                    else f"{category}{FlextLdifConstants.ServerDetection.LDIF_FILE_EXTENSION}"
                )
                output_path = Path(str(output_dir)) / category_filename
                output_files_info[category] = str(output_path)

            return {
                "total_entries": total_entries,
                "categorized": categorized_counts,
                "rejection_rate": rejection_rate,
                "rejection_count": rejection_count,
                "rejection_reasons": rejection_reasons,
                "written_counts": written_counts,
                "output_files": output_files_info,
            }

    class AclUtils(FlextUtilities):
        """ACL utilities with shared helper methods for ACL processing.

        This class provides common ACL component creation and validation
        logic used across ACL parser and service modules, following FLEXT
        utility class patterns for centralized functionality.
        """

        class ComponentFactory:
            """Factory for creating and validating ACL components with railway pattern."""

            @staticmethod
            def create_acl_components() -> FlextResult[
                tuple[
                    FlextLdifModels.AclTarget,
                    FlextLdifModels.AclSubject,
                    FlextLdifModels.AclPermissions,
                ]
            ]:
                """Create ACL components with proper validation using railway pattern.

                Returns:
                    FlextResult containing tuple of (target, subject, permissions) on success,
                    or failure with descriptive error message.

                """
                # Create ACL components using direct instantiation
                target_result = FlextResult.ok(
                    FlextLdifModels.AclTarget(
                        target_dn=FlextLdifConstants.ServerDetection.ACL_WILDCARD_DN
                    )
                )
                subject_result = FlextResult.ok(
                    FlextLdifModels.AclSubject(
                        subject_type=FlextLdifConstants.ServerDetection.ACL_WILDCARD_TYPE,
                        subject_value=FlextLdifConstants.ServerDetection.ACL_WILDCARD_VALUE,
                    )
                )
                perms_result = FlextResult.ok(FlextLdifModels.AclPermissions(read=True))

                # Early return on first failure
                if target_result.is_failure:
                    return FlextResult.fail(
                        f"Failed to create AclTarget: {target_result.error}"
                    )

                if subject_result.is_failure:
                    return FlextResult.fail(
                        f"Failed to create AclSubject: {subject_result.error}"
                    )

                if perms_result.is_failure:
                    return FlextResult.fail(
                        f"Failed to create AclPermissions: {perms_result.error}"
                    )

                # Type safety validation
                target = target_result.unwrap()
                subject = subject_result.unwrap()
                permissions = perms_result.unwrap()

                if not isinstance(target, FlextLdifModels.AclTarget):
                    return FlextResult.fail(
                        "Created object is not an AclTarget instance"
                    )

                if not isinstance(subject, FlextLdifModels.AclSubject):
                    return FlextResult.fail(
                        "Created object is not an AclSubject instance"
                    )

                if not isinstance(permissions, FlextLdifModels.AclPermissions):
                    return FlextResult.fail(
                        "Created object is not an AclPermissions instance"
                    )

                return FlextResult.ok((target, subject, permissions))

            @staticmethod
            def create_unified_acl(
                name: str,
                target: FlextLdifModels.AclTarget,
                subject: FlextLdifModels.AclSubject,
                permissions: FlextLdifModels.AclPermissions,
                server_type: FlextLdifTypes.AclServerType,
                raw_acl: str,
            ) -> FlextResult[FlextLdifModels.Acl]:
                """Create unified ACL with proper validation using railway pattern.

                Uses consolidated Acl model with server_type discriminator.

                Args:
                    name: ACL name
                    target: ACL target component
                    subject: ACL subject component
                    permissions: ACL permissions component
                    server_type: Server type (openldap, oid, etc.)
                    raw_acl: Original ACL string

                Returns:
                    FlextResult containing Acl instance on success, failure otherwise.

                """
                try:
                    # Validate server_type is supported
                    supported_servers = {
                        FlextLdifConstants.LdapServers.OPENLDAP,
                        FlextLdifConstants.LdapServers.OPENLDAP_2,
                        FlextLdifConstants.LdapServers.OPENLDAP_1,
                        FlextLdifConstants.LdapServers.ORACLE_OID,
                        FlextLdifConstants.LdapServers.ORACLE_OUD,
                        FlextLdifConstants.LdapServers.DS_389,
                    }

                    # Default to OpenLDAP for generic/unknown server types
                    effective_server_type = (
                        server_type
                        if server_type in supported_servers
                        else FlextLdifConstants.LdapServers.OPENLDAP
                    )

                    # Create ACL using consolidated Acl model
                    unified_acl = FlextLdifModels.Acl(
                        name=name,
                        target=target,
                        subject=subject,
                        permissions=permissions,
                        server_type=effective_server_type,
                        raw_acl=raw_acl,
                    )

                    # Verify created instance is correct type
                    if not isinstance(unified_acl, FlextLdifModels.Acl):
                        return FlextResult[FlextLdifModels.Acl].fail(
                            "Created object is not an Acl instance"
                        )

                    return FlextResult[FlextLdifModels.Acl].ok(unified_acl)
                except (ValueError, TypeError, AttributeError) as e:
                    return FlextResult[FlextLdifModels.Acl].fail(
                        f"Failed to create ACL: {e}"
                    )

    @staticmethod
    def normalize_server_type_for_literal(
        server_type: str,
    ) -> FlextLdifConstants.LiteralTypes.ServerType:
        """Normalize server type from short form to Literal-compatible long form.

        Converts short-form server type identifiers (e.g., "oid", "oud")
        to long-form identifiers required by LiteralTypes.ServerType
        (e.g., "oracle_oid", "oracle_oud").

        Args:
            server_type: Short-form server type identifier

        Returns:
            Long-form server type compatible with LiteralTypes.ServerType

        """
        # Map short forms to long forms for Literal validation
        server_type_map: dict[str, FlextLdifConstants.LiteralTypes.ServerType] = {
            "oid": "oracle_oid",
            "oud": "oracle_oud",
            # All other types are already in long form or match directly
            "active_directory": "active_directory",
            "openldap": "openldap",
            "openldap2": "openldap2",
            "openldap1": "openldap1",
            "apache_directory": "apache_directory",
            "novell_edirectory": "novell_edirectory",
            "ibm_tivoli": "ibm_tivoli",
            "generic": "generic",
            "389ds": "389ds",
        }

        # Return mapped value or default to generic if unknown
        return server_type_map.get(server_type, "generic")


__all__ = ["FlextLdifUtilities"]
