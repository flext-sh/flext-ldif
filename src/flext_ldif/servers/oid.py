"""Oracle Internet Directory (OID) Servers."""

from __future__ import annotations

from flext_ldif.servers.rfc import FlextLdifServersRfc

from ._oid.acl import FlextLdifServersOidAcl
from ._oid.acl_assemble import FlextLdifServersOidAclAssemble
from ._oid.acl_convert import FlextLdifServersOidAclConvert
from ._oid.acl_convert_oud import FlextLdifServersOidAclToOud
from ._oid.acl_pipeline import FlextLdifServersOidAclPipeline
from ._oid.acl_render import FlextLdifServersOidAclRender
from ._oid.entry import FlextLdifServersOidEntry
from ._oid.schema import FlextLdifServersOidSchema
from ._oid.server_constants import FlextLdifServersOidConstants


class FlextLdifServersOid(FlextLdifServersRfc):
    """Oracle OID server servers - implements t.JsonValue."""

    class Constants(FlextLdifServersOidConstants):
        """OID server constants."""

    class Acl(FlextLdifServersOidAcl):
        """OID ACL server."""

    class Schema(FlextLdifServersOidSchema):
        """OID Schema server."""

    class Entry(FlextLdifServersOidEntry):
        """OID Entry server."""


# Why: FlextLdifServersOidAcl is excluded here (unlike its Constants/Entry/
# Schema siblings) because the frozen root API-freeze contract
# (tests/unit/test_api_freeze.py::PRIVATE_ROOT_SYMBOLS) declares Oid/Oud/Rfc
# Acl implementation classes private at the package root; the root generator
# mirrors this module's __all__, so leaving it out here is what keeps it out
# of flext_ldif.__all__. The remaining Acl helper classes stay listed so
# their module-level test re-export (tests/unit/servers/test_oid_acl_*.py)
# satisfies ruff F401 without leaking further up the generated chain.
__all__: list[str] = [
    "FlextLdifServersOid",
    "FlextLdifServersOidAclAssemble",
    "FlextLdifServersOidAclConvert",
    "FlextLdifServersOidAclPipeline",
    "FlextLdifServersOidAclRender",
    "FlextLdifServersOidAclToOud",
    "FlextLdifServersOidConstants",
    "FlextLdifServersOidEntry",
    "FlextLdifServersOidSchema",
    "FlextLdifServersRfc",
]
