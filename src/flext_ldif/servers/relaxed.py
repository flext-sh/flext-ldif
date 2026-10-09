"""Relaxed Servers for Lenient LDIF Processing.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import ClassVar, override

from flext_ldif import c, m, p, r, t
from flext_ldif.servers._relaxed.server_constants import (
    FlextLdifServersRelaxedConstants,
)
from flext_ldif.servers._rfc.acl import FlextLdifServersRfcAcl
from flext_ldif.servers.relaxed_entry import FlextLdifServersRelaxedEntry
from flext_ldif.servers.relaxed_schema import FlextLdifServersRelaxedSchema
from flext_ldif.servers.rfc import FlextLdifServersRfc


class FlextLdifServersRelaxed(FlextLdifServersRfc):
    """Relaxed mode server servers for non-compliant LDIF."""

    Constants: ClassVar[type[FlextLdifServersRelaxedConstants]] = (
        FlextLdifServersRelaxedConstants
    )
    Schema: ClassVar[type[FlextLdifServersRelaxedSchema]] = (
        FlextLdifServersRelaxedSchema
    )
    Entry: ClassVar[type[FlextLdifServersRelaxedEntry]] = FlextLdifServersRelaxedEntry

    class Acl(FlextLdifServersRfcAcl):
        """Relaxed ACL server for lenient LDIF processing."""

        @override
        def can_handle(self, acl_line: str | m.Ldif.Acl | t.JsonValue) -> bool:
            """Accept any ACL line in relaxed mode.

            Returns:
                The resulting ``bool``.
            """
            return self.can_handle_acl(acl_line)

        @override
        def can_handle_acl(self, acl_line: str | m.Ldif.Acl | t.JsonValue) -> bool:
            """Accept any ACL line in relaxed mode.

            Returns:
                The resulting ``bool``.
            """
            _ = acl_line
            return True

        @override
        def can_handle_attribute(self, attribute: m.Ldif.SchemaAttribute) -> bool:
            """Check if this ACL server should be aware of a specific attribute.

            definition.

            Returns:
                The resulting ``bool``.
            """
            _ = attribute
            return True

        @override
        def can_handle_objectclass(self, objectclass: m.Ldif.SchemaObjectClass) -> bool:
            """Check if this ACL server should be aware of a specific objectClass.

            definition.

            Returns:
                The resulting ``bool``.
            """
            _ = objectclass
            return True

        @override
        def _parse_acl(self, acl_line: str) -> p.Result[m.Ldif.Acl]:
            """Parse ACL with best-effort approach.

            Returns:
                The resulting ``p.Result[m.Ldif.Acl]``.
            """
            if not acl_line or not acl_line.strip():
                return r[m.Ldif.Acl].fail("ACL line cannot be empty")
            try:
                return self._parse_relaxed_acl(acl_line)
            except c.Ldif.EXC_LDIF_PARSE as e:
                self.logger.debug("Relaxed ACL parse failed: %s", e)
                return r[m.Ldif.Acl].fail(f"Failed to parse ACL: {e}", exception=e)

        def _parse_relaxed_acl(self, acl_line: str) -> p.Result[m.Ldif.Acl]:
            """Parse ACL using RFC first, then relaxed fallback.

            Returns:
                The resulting ``p.Result[m.Ldif.Acl]``.
            """
            parent_result = super()._parse_acl(acl_line)
            if parent_result.success:
                updated_acl = self._with_relaxed_acl_metadata(
                    parent_result.value,
                    acl_line,
                )
                return r[m.Ldif.Acl].ok(updated_acl)
            relaxed_acl = self._build_relaxed_acl(acl_line)
            return r[m.Ldif.Acl].ok(relaxed_acl)

        def _with_relaxed_acl_metadata(
            self,
            acl: m.Ldif.Acl,
            acl_line: str,
        ) -> m.Ldif.Acl:
            """Attach relaxed metadata to an ACL.

            Returns:
                The resulting ``m.Ldif.Acl``.
            """
            if not acl.metadata:
                acl_with_metadata: m.Ldif.Acl = acl.model_copy(
                    update={
                        "metadata": m.Ldif.ServerMetadata.model_validate({
                            "server_type": self._get_server_type(),
                            "extensions": {"original_format": acl_line.strip()},
                        }),
                    },
                )
                return acl_with_metadata
            updated_extensions: t.MutableJsonMapping = acl.metadata.extensions or {}
            updated_metadata = acl.metadata.model_copy(
                update={
                    "server_type": self._get_server_type(),
                    "extensions": updated_extensions,
                },
            )
            updated_acl: m.Ldif.Acl = acl.model_copy(
                update={"metadata": updated_metadata},
            )
            return updated_acl

        def _build_relaxed_acl(self, acl_line: str) -> m.Ldif.Acl:
            """Build relaxed ACL fallback model.

            Returns:
                The resulting ``m.Ldif.Acl``.
            """
            relaxed_acl: m.Ldif.Acl = m.Ldif.Acl.model_validate({
                "name": FlextLdifServersRelaxedConstants.ACL_DEFAULT_NAME,
                "target": m.Ldif.AclTarget.model_validate({
                    "target_dn": (
                        FlextLdifServersRelaxedConstants.ACL_DEFAULT_TARGET_DN
                    ),
                    "attributes": [],
                }),
                "subject": m.Ldif.AclSubject.model_validate({
                    "subject_type": "all",
                    "subject_value": (
                        FlextLdifServersRelaxedConstants.ACL_DEFAULT_SUBJECT_VALUE
                    ),
                }),
                "permissions": m.Ldif.AclPermissions.model_validate({}),
                "server_type": self._get_server_type(),
                "validation_violations": [],
                "raw_line": acl_line,
                "raw_acl": acl_line,
                "metadata": m.Ldif.ServerMetadata.model_validate({
                    "server_type": self._get_server_type(),
                    "extensions": {"original_format": acl_line.strip()},
                }),
            })
            return relaxed_acl

        @override
        def _write_acl(self, acl_data: m.Ldif.Acl) -> p.Result[str]:
            """Write ACL to RFC format - stringify in relaxed mode.

            Returns:
                The resulting ``p.Result[str]``.
            """
            parent_result = super()._write_acl(acl_data)
            if parent_result.success:
                return parent_result
            if acl_data.raw_acl:
                return r[str].ok(acl_data.raw_acl)
            acl_name = (
                acl_data.name or FlextLdifServersRelaxedConstants.ACL_DEFAULT_NAME
            )
            return r[str].ok(
                f"{FlextLdifServersRelaxedConstants.ACL_WRITE_PREFIX}{acl_name}",
            )


__all__: list[str] = ["FlextLdifServersRelaxed"]
