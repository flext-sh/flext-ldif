"""Oracle Internet Directory (OID) Servers."""

from __future__ import annotations

from flext_ldif.servers._oid.acl import FlextLdifServersOidAcl
from flext_ldif.servers._oid.acl_assemble import FlextLdifServersOidAclAssemble
from flext_ldif.servers._oid.acl_convert import FlextLdifServersOidAclConvert
from flext_ldif.servers._oid.acl_convert_oud import FlextLdifServersOidAclToOud
from flext_ldif.servers._oid.acl_pipeline import FlextLdifServersOidAclPipeline
from flext_ldif.servers._oid.acl_render import FlextLdifServersOidAclRender
from flext_ldif.servers._oid.constants import FlextLdifServersOidConstants
from flext_ldif.servers._oid.entry import FlextLdifServersOidEntry
from flext_ldif.servers._oid.schema import FlextLdifServersOidSchema
from flext_ldif.servers.rfc import FlextLdifServersRfc


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


__all__: list[str] = [
    "FlextLdifServersOid",
    "FlextLdifServersOidAcl",
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
