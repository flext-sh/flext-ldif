# AUTO-GENERATED FILE — Regenerate with: make gen
"""LDIF protocol facade.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from flext_cli import FlextCliProtocols

from flext_ldif._protocols import (
    FlextLdifProtocolsBase,
    FlextLdifProtocolsClient,
    FlextLdifProtocolsDomain,
    FlextLdifProtocolsLdap3,
    FlextLdifProtocolsValues,
)


class FlextLdifProtocols(FlextCliProtocols):
    """Unified LDIF protocol facade."""

    @runtime_checkable
    class Ldif(
        FlextLdifProtocolsDomain,
        FlextLdifProtocolsBase,
        FlextLdifProtocolsLdap3,
        FlextLdifProtocolsValues,
        FlextLdifProtocolsClient,
        Protocol,
    ):
        """LDIF-specific structural protocol namespace.

        ``LdifSettings``, ``Settings``, and ``ServerResolutionService`` have a
        single owner in ``FlextLdifProtocolsBase`` and are inherited unchanged.
        """

        # Entry protocols
        Entry: type[FlextLdifProtocolsBase.Entry] = FlextLdifProtocolsBase.Entry
        ChangeOperation: type[FlextLdifProtocolsBase.ChangeOperation] = (
            FlextLdifProtocolsBase.ChangeOperation
        )
        ChangeOperationValue: type[FlextLdifProtocolsBase.ChangeOperationValue] = (
            FlextLdifProtocolsBase.ChangeOperationValue
        )
        Control: type[FlextLdifProtocolsBase.Control] = FlextLdifProtocolsBase.Control

        # ACL protocols
        Acl: type[FlextLdifProtocolsBase.Acl] = FlextLdifProtocolsBase.Acl
        AclAllow: type[FlextLdifProtocolsBase.AclTarget] = (
            FlextLdifProtocolsBase.AclTarget
        )
        AclPermissions: type[FlextLdifProtocolsBase.AclPermissions] = (
            FlextLdifProtocolsBase.AclPermissions
        )
        AclResponse: type[FlextLdifProtocolsBase.AclResponse] = (
            FlextLdifProtocolsBase.AclResponse
        )
        AclEvaluationResult: type[FlextLdifProtocolsBase.AclEvaluationResult] = (
            FlextLdifProtocolsBase.AclEvaluationResult
        )

        # Server protocols
        ServerServer: type[FlextLdifProtocolsBase.ServerServer] = (
            FlextLdifProtocolsBase.ServerServer
        )
        SchemaServer: type[FlextLdifProtocolsBase.SchemaServer] = (
            FlextLdifProtocolsBase.SchemaServer
        )
        AclServer: type[FlextLdifProtocolsBase.AclServer] = (
            FlextLdifProtocolsBase.AclServer
        )
        EntryServer: type[FlextLdifProtocolsBase.EntryServer] = (
            FlextLdifProtocolsBase.EntryServer
        )
        ServerRegistry: type[FlextLdifProtocolsBase.ServerRegistry] = (
            FlextLdifProtocolsBase.ServerRegistry
        )
        RegistryBound: type[FlextLdifProtocolsBase.ServerReference] = (
            FlextLdifProtocolsBase.ServerReference
        )
        ServerConstants: type[FlextLdifProtocolsBase.ServerConstants] = (
            FlextLdifProtocolsBase.ServerConstants
        )

        # Schema protocols
        SchemaAttribute: type[FlextLdifProtocolsBase.SchemaAttribute] = (
            FlextLdifProtocolsBase.SchemaAttribute
        )
        SchemaObjectClass: type[FlextLdifProtocolsBase.SchemaObjectClass] = (
            FlextLdifProtocolsBase.SchemaObjectClass
        )
        SchemaItemKind: type[FlextLdifProtocolsBase.SchemaItemKind] = (
            FlextLdifProtocolsBase.SchemaItemKind
        )

        # Dynamic counts
        DynamicCounts: type[FlextLdifProtocolsBase.DynamicCounts] = (
            FlextLdifProtocolsBase.DynamicCounts
        )

        # Validation service
        ValidationService: type[FlextLdifProtocolsBase.ValidationService] = (
            FlextLdifProtocolsBase.ValidationService
        )

        # Server detection
        ServerDetectionService: type[FlextLdifProtocolsBase.ServerDetectionService] = (
            FlextLdifProtocolsBase.ServerDetectionService
        )
        ServerDetectionResult: type[FlextLdifProtocolsBase.ServerDetectionResult] = (
            FlextLdifProtocolsBase.ServerDetectionResult
        )

        # Server resolution
        ServerResolutionService: type[
            FlextLdifProtocolsBase.ServerResolutionService
        ] = FlextLdifProtocolsBase.ServerResolutionService


p = FlextLdifProtocols

__all__: list[str] = ["FlextLdifProtocols", "p"]
