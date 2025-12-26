"""Oracle Unified Directory (OUD) Quirks.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

Provides OUD-specific quirks for schema, ACL, and entry processing.
"""

from __future__ import annotations

from flext_core import FlextLogger

from flext_ldif.servers._oud import (
    FlextLdifServersOudAcl,
    FlextLdifServersOudConstants,
    FlextLdifServersOudEntry,
    FlextLdifServersOudSchema,
)
from flext_ldif.servers.rfc import FlextLdifServersRfc

logger = FlextLogger(__name__)


class FlextLdifServersOud(FlextLdifServersRfc):
    """Oracle Unified Directory (OUD) Server Implementation.

    Extends RFC baseline (RFC 2849/4512) with Oracle OUD-specific features.
    OUD implements RFC 4876 Access Control Model with significant extensions.

    RFC vs OUD Differences Summary
    ==============================

    **ACI Format (RFC 4876 vs OUD Extensions)**:

    RFC defines basic ACI structure, OUD extends with:

    - **Syntax**: ``aci: (target)(version 3.0;acl "name";permissionBindRules;)``
    - **Targets**: target, targetattr, targetfilter, targetscope, targattrfilters,
      targetcontrol, extop
    - **Permissions**: read, write, add, delete, search, compare, selfwrite, proxy,
      import, export, all (RFC only has read, write, add, delete, search, compare)
    - **Bind Rules**: userdn, groupdn, roledn, ip, dns, timeofday, dayofweek,
      authmethod, ssf (RFC only defines userdn, groupdn)

    **Schema Extensions (RFC 4512 vs OUD)**:

    - RFC 4512 defines attributeTypes and objectClasses syntax
    - OUD adds X-* extensions: X-ORIGIN, X-SCHEMA-FILE, X-PATTERN, X-ENUM
    - OUD allows non-numeric OIDs with ``-oid`` suffix
    - OUD uses namespace ``1.3.6.1.4.1.26027.*`` for custom schemas

    **Entry Extensions**:

    - OUD uses operational attributes: ds-cfg-*, ds-sync-*, ds-privilege-name
    - OUD uses DN case preservation (case-insensitive but case-preserving)
    - OUD supports multi-line ACIs with continuation (space + content)

    Example OUD ACI (from Oracle Docs)
    ----------------------------------

    Single permission::

        aci: (targetattr="*")(version 3.0; acl "OracleContext accessible by Admins";
             allow (all) groupdn="ldap:///cn=OracleContextAdmins,cn=groups,dc=example,dc=com";)

    Multiple bind rules::

        aci: (targetattr="*")(version 3.0; acl "Multi-group access";
             allow (read,search,write,selfwrite,compare)
             groupdn="ldap:///cn=OracleDASUserPriv,cn=Groups,cn=OracleContext";
             allow (read,search,compare) userdn="ldap:///anyone";)

    Attribute exclusion::

        aci: (targetattr!="userpassword||authpassword||aci")
             (version 3.0; acl "Anonymous read access"; allow (read,search,compare)
             userdn="ldap:///anyone";)

    Inheritance Hierarchy
    ---------------------

    ``FlextLdifServersBase (ABC)`` → ``FlextLdifServersRfc`` → ``FlextLdifServersOud``

    Hooks System (from base.py)
    ---------------------------

    - ``_hook_post_parse_attribute()`` - OUD X-* extension handling
    - ``_hook_post_parse_objectclass()`` - OUD objectClass extensions
    - ``_hook_post_parse_acl()`` - OUD ACI format normalization
    - ``_hook_validate_entry_raw()`` - OUD entry validation
    - ``_hook_post_parse_entry()`` - OUD operational attribute handling
    - ``_hook_pre_write_entry()`` - OUD LDIF formatting

    Official Documentation
    ----------------------

    - ACI Syntax: https://docs.oracle.com/cd/E22289_01/html/821-1277/aci-syntax.html
    - Managing ACIs: https://docs.oracle.com/cd/E22289_01/html/821-1273/managing-acis-with-ldapmodify.html
    - Schema: https://docs.oracle.com/en/middleware/idm/unified-directory/14.1.2/oudag/managing-directory-schema.html

    """

    # =========================================================================
    # Server identification - accessed via Constants via properties in base.py
    # =========================================================================
    # NOTE: server_type and priority are accessed via properties in base.py
    # which read from Constants.SERVER_TYPE and Constants.PRIORITY

    # === PUBLIC INTERFACE FOR SCHEMA CONFIGURATION ===

    class Constants(FlextLdifServersOudConstants):
        """OUD server constants."""

    class Acl(FlextLdifServersOudAcl):  # type: ignore[override]
        """OUD ACL quirk."""

    class Schema(FlextLdifServersOudSchema):
        """OUD Schema quirk."""

    class Entry(FlextLdifServersOudEntry):
        """OUD Entry quirk."""


__all__ = ["FlextLdifServersOud"]
