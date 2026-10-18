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
    # Entry protocols
    EntryProtocol,
    ChangeOperationProtocol,
    ChangeOperationValueProtocol,
    ControlProtocol,
    # ACL protocols
    AclProtocol,
    AclAllowProtocol,
    AclPermissionsProtocol,
    AclResponseProtocol,
    AclEvaluationResultProtocol,
    # Server protocols
    ServerServerProtocol,
    SchemaServerProtocol,
    AclServerProtocol,
    EntryServerProtocol,
    ServerRegistryProtocol,
    RegistryBoundProtocol,
    ServerConstantsProtocol,
    # Schema protocols
    SchemaAttributeProtocol,
    SchemaObjectClassProtocol,
    SchemaItemKindProtocol,
    # Dynamic counts
    DynamicCountsProtocol,
    # Validation service
    ValidationServiceProtocol,
    # Server detection
    ServerDetectionServiceProtocol,
    ServerDetectionResultProtocol,
    # Server resolution
    ServerResolutionServiceProtocol,
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
        Entry: type[EntryProtocol] = EntryProtocol
        ChangeOperation: type[ChangeOperationProtocol] = ChangeOperationProtocol
        ChangeOperationValue: type[ChangeOperationValueProtocol] = ChangeOperationValueProtocol
        Control: type[ControlProtocol] = ControlProtocol

        # ACL protocols
        Acl: type[AclProtocol] = AclProtocol
        AclAllow: type[AclAllowProtocol] = AclAllowProtocol
        AclPermissions: type[AclPermissionsProtocol] = AclPermissionsProtocol
        AclResponse: type[AclResponseProtocol] = AclResponseProtocol
        AclEvaluationResult: type[AclEvaluationResultProtocol] = AclEvaluationResultProtocol

        # Server protocols
        ServerServer: type[ServerServerProtocol] = ServerServerProtocol
        SchemaServer: type[SchemaServerProtocol] = SchemaServerProtocol
        AclServer: type[AclServerProtocol] = AclServerProtocol
        EntryServer: type[EntryServerProtocol] = EntryServerProtocol
        ServerRegistry: type[ServerRegistryProtocol] = ServerRegistryProtocol
        RegistryBound: type[RegistryBoundProtocol] = RegistryBoundProtocol
        ServerConstants: type[ServerConstantsProtocol] = ServerConstantsProtocol

        # Schema protocols
        SchemaAttribute: type[SchemaAttributeProtocol] = SchemaAttributeProtocol
        SchemaObjectClass: type[SchemaObjectClassProtocol] = SchemaObjectClassProtocol
        SchemaItemKind: type[SchemaItemKindProtocol] = SchemaItemKindProtocol

        # Dynamic counts
        DynamicCounts: type[DynamicCountsProtocol] = DynamicCountsProtocol

        # Validation service
        ValidationService: type[ValidationServiceProtocol] = ValidationServiceProtocol

        # Server detection
        ServerDetectionService: type[ServerDetectionServiceProtocol] = ServerDetectionServiceProtocol
        ServerDetectionResult: type[ServerDetectionResultProtocol] = ServerDetectionResultProtocol

        # Server resolution
        ServerResolutionService: type[ServerResolutionServiceProtocol] = ServerResolutionServiceProtocol


p = FlextLdifProtocols

__all__: list[str] = ["FlextLdifProtocols", "p"]