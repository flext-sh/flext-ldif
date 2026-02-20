"""ACL Service - Direct ACL Processing with flext-core APIs."""

from __future__ import annotations

from collections.abc import Sequence

from flext_core import FlextLogger, r

from flext_ldif._models.domain import FlextLdifModelsDomains
from flext_ldif._utilities.acl import FlextLdifUtilitiesACL
from flext_ldif._utilities.entry import FlextLdifUtilitiesEntry
from flext_ldif._utilities.server import FlextLdifUtilitiesServer
from flext_ldif.base import s
from flext_ldif.models import m
from flext_ldif.services.server import FlextLdifServer
from flext_ldif.utilities import u


class FlextLdifAcl(s[m.Ldif.LdifResults.AclResponse]):
    """Direct ACL processing service using flext-core APIs."""

    _server: FlextLdifServer

    def __init__(self, server: FlextLdifServer | None = None) -> None:
        """Initialize ACL service with optional server instance."""
        super().__init__()

        object.__setattr__(
            self,
            "_server",
            (server if server is not None else FlextLdifServer.get_global_instance()),
        )

    @staticmethod
    def _build_acl_response(
        acls: Sequence[FlextLdifModelsDomains.Acl],
        *,
        processed_entries: int = 1,
        failed_entries: int = 0,
    ) -> m.Ldif.LdifResults.AclResponse:
        return m.Ldif.LdifResults.AclResponse(
            acls=list(acls),
            statistics=m.Ldif.LdifResults.Statistics(
                processed_entries=processed_entries,
                acls_extracted=len(acls),
                failed_entries=failed_entries,
            ),
        )

    def parse_acl_string(
        self,
        acl_string: str,
        server_type: str,
    ) -> r[m.Ldif.Acl]:
        """Parse ACL string using server-specific quirks."""
        original_server_type = str(server_type)
        try:
            normalized_server_type = FlextLdifUtilitiesServer.normalize_server_type(
                original_server_type,
            )
        except (ValueError, TypeError) as e:
            return r[m.Ldif.Acl].fail(f"Invalid server type: {server_type} - {e}")

        try:
            if original_server_type == "openldap":
                acl_quirk = self._server.acl("openldap1")
                if acl_quirk is None:
                    acl_quirk = self._server.acl("openldap2")
            else:
                acl_quirk = self._server.acl(normalized_server_type)
        except ValueError as e:
            return r[m.Ldif.Acl].fail(str(e))
        if acl_quirk is None:
            return r[m.Ldif.Acl].fail(
                f"No ACL quirk found for server type: {normalized_server_type}",
            )

        parse_result = acl_quirk.parse(acl_string)

        if parse_result.is_failure:
            return r[m.Ldif.Acl].fail(parse_result.error or "ACL parsing failed")

        return r[m.Ldif.Acl].ok(parse_result.value)

    def write_acl(
        self,
        acl: m.Ldif.Acl,
        server_type: str,
    ) -> r[str]:
        """Write ACL model to string format."""
        acl_quirk = self._server.acl(server_type)
        if acl_quirk is None:
            return r[str].fail(
                f"No ACL quirk found for server type: {server_type}",
            )

        write_result = acl_quirk.write(acl)

        if write_result.is_failure:
            return r[str].fail(write_result.error or "ACL writing failed")

        return r[str].ok(write_result.value)

    def extract_acls_from_entry(
        self,
        entry: m.Ldif.Entry,
        server_type: str,
    ) -> r[m.Ldif.LdifResults.AclResponse]:
        """Extract ACLs from entry using server-specific attribute names."""
        acl_attr_name = FlextLdifUtilitiesACL.get_acl_attributes(
            server_type,
        )

        if not acl_attr_name:
            return r[m.Ldif.LdifResults.AclResponse].ok(
                self._build_acl_response([]),
            )

        acl_values = entry.get_attribute_values(
            next(iter(acl_attr_name)),
        )

        if not acl_values:
            return r[m.Ldif.LdifResults.AclResponse].ok(
                self._build_acl_response([]),
            )

        acls: list[FlextLdifModelsDomains.Acl] = []
        failed_count = 0

        def parse_acl_wrapper(acl_value: str) -> m.Ldif.Acl:
            """Parse single ACL value - returns Acl directly for batch compatibility."""
            nonlocal failed_count
            parse_result = self.parse_acl_string(acl_value, server_type)
            if parse_result.is_success:
                return parse_result.value
            failed_count += 1
            logger = FlextLogger(__name__)
            logger.warning(
                "Failed to parse ACL value",
                error=parse_result.error,
                server_type=server_type,
            )
            msg = parse_result.error or "Failed to parse ACL"
            raise ValueError(msg)

        batch_result = u.Collection.batch(
            list(acl_values),
            parse_acl_wrapper,
            on_error="skip",
        )
        if batch_result.is_success:
            results_raw = batch_result.value.results

            acls.extend(item for item in results_raw if isinstance(item, m.Ldif.Acl))

        return r[m.Ldif.LdifResults.AclResponse].ok(
            self._build_acl_response(acls, failed_entries=failed_count),
        )

    @staticmethod
    def extract_acl_entries(
        entries: list[m.Ldif.Entry],
        acl_attributes: list[str] | None = None,
    ) -> r[list[m.Ldif.Entry]]:
        """Extract entries that contain ACL attributes."""
        if not entries:
            return r[list[m.Ldif.Entry]].ok([])

        if acl_attributes is None:
            acl_attributes = list(
                FlextLdifUtilitiesACL.get_acl_attributes(None),
            )

        def has_acl_attribute(entry: m.Ldif.Entry) -> bool:
            """Check if entry has at least one ACL attribute."""
            if FlextLdifAcl._is_schema_entry(entry):
                return False

            for attr_name in acl_attributes:
                attr_values = entry.get_attribute_values(attr_name)
                if u.Guards.is_list_non_empty(attr_values):
                    return True
            return False

        acl_entries: list[m.Ldif.Entry] = [
            entry for entry in entries if has_acl_attribute(entry)
        ]

        return r[list[m.Ldif.Entry]].ok(acl_entries)

    @staticmethod
    def _is_schema_entry(entry: m.Ldif.Entry) -> bool:
        """Check if entry is a schema entry."""
        return FlextLdifUtilitiesEntry.is_schema_entry(entry, strict=False)

    @staticmethod
    def evaluate_acl_context(
        acls: list[m.Ldif.Acl],
        required_permissions: m.Ldif.LdifResults.AclPermissions | dict[str, bool],
    ) -> r[m.Ldif.LdifResults.AclEvaluationResult]:
        """Evaluate if ACLs grant required permissions."""
        required = (
            m.Ldif.LdifResults.AclPermissions(**required_permissions)
            if isinstance(required_permissions, dict)
            else required_permissions
        )

        if not acls:
            return r[m.Ldif.LdifResults.AclEvaluationResult].ok(
                m.Ldif.LdifResults.AclEvaluationResult(
                    granted=False,
                    matched_acl=None,
                    message="No ACLs to evaluate - access denied by default",
                ),
            )

        perm_names = ["read", "write", "delete", "add", "search", "compare"]
        required_perms = [p for p in perm_names if getattr(required, p, False)]

        if not required_perms:
            return r[m.Ldif.LdifResults.AclEvaluationResult].ok(
                m.Ldif.LdifResults.AclEvaluationResult(
                    granted=True,
                    matched_acl=acls[0] if acls else None,
                    message="No permissions required - access granted trivially",
                ),
            )

        def acl_grants_all(acl: m.Ldif.Acl) -> bool:
            """Check if ACL grants all required permissions."""
            return all(getattr(acl.permissions, perm, False) for perm in required_perms)

        def predicate(value: m.Ldif.Acl) -> bool:
            """Check if ACL grants all permissions."""
            return acl_grants_all(value)

        found_raw = u.find(acls, predicate=predicate)

        if found_raw is not None:
            return r[m.Ldif.LdifResults.AclEvaluationResult].ok(
                m.Ldif.LdifResults.AclEvaluationResult(
                    granted=True,
                    matched_acl=found_raw,
                    message=f"ACL '{found_raw.name}' grants required permissions: {required_perms}",
                ),
            )

        return r[m.Ldif.LdifResults.AclEvaluationResult].ok(
            m.Ldif.LdifResults.AclEvaluationResult(
                granted=False,
                matched_acl=None,
                message=f"No ACL grants required permissions: {required_perms}",
            ),
        )

    def execute(self) -> r[m.Ldif.LdifResults.AclResponse]:
        """Execute ACL service health check."""
        return r[m.Ldif.LdifResults.AclResponse].ok(
            m.Ldif.LdifResults.AclResponse(
                acls=[],
                statistics=m.Ldif.LdifResults.Statistics(),
            ),
        )


__all__ = ["FlextLdifAcl"]
