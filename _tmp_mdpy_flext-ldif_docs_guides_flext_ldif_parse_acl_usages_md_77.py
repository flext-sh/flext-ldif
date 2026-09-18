# from flext-ldif_docs/guides/flext_ldif_parse_acl_usages.md:77
from __future__ import annotations


class Acl(Protocol):
    """Protocol for ACL servers."""

    def parse(self, acl_line: str) -> p.Result[t.JsonMapping]:
        """Parse ACL - returns r with dict or Acl model."""```
______________________________________________________________________

## 2. SERVER SERVERS IMPLEMENTATIONS

### 13 Server Servers Classes Implementing parse()

| #   | File            | Location                                   | Server Type             |
| --- | --------------- | ------------------------------------------ | ----------------------- |
| 1   | `oid.py`        | `/flext_ldif/servers/servers/oid.py`        | Oracle OID              |
| 2   | `ouds.py`       | `/flext_ldif/servers/servers/ouds.py`       | Oracle OUD              |
| 3   | `openldap.py`   | `/flext_ldif/servers/servers/openldap.py`   | OpenLDAP (generic)      |
| 4   | `openldap1.py`  | `/flext_ldif/servers/servers/openldap1.py`  | OpenLDAP 1.x            |
| 5   | `openldap2s.py` | `/flext_ldif/servers/servers/openldap2s.py` | OpenLDAP 2.x            |
| 6   | `tivoli.py`     | `/flext_ldif/servers/servers/tivoli.py`     | IBM Tivoli              |
| 7   | `novell.py`     | `/flext_ldif/servers/servers/novell.py`     | Novell eDirectory       |
| 8   | `ad.py`         | `/flext_ldif/servers/servers/ad.py`         | Active Directory        |
| 9   | `ds389.py`      | `/flext_ldif/servers/servers/ds389.py`      | 389 Directory Server    |
| 10  | `apache.py`     | `/flext_ldif/servers/servers/apache.py`     | Apache DS               |
| 11  | `relaxed.py`    | `/flext_ldif/servers/servers/relaxed.py`    | RFC-compliant (relaxed) |
| 12  | `rfcs.py`       | `/flext_ldif/servers/servers/rfcs.py`       | RFC baseline            |
| 13  | `generics.py`   | `/flext_ldif/servers/servers/generics.py`   | Generic fallback        |

### Implementation Pattern

Each server servers class has:

- `class XyzAcl(FlextLdifServersBase.Acl):`
- `def parse(self, acl_line: str) -> p.Result[FlextLdifModels.Acl]:`
- Server-specific parsing logic
- Returns `r.ok(Acl(...))` or `r.fail(...)`

**Affected Lines**: ~40-50 lines per file × 13 files = ~520-650 lines

______________________________________________________________________

## 3. SERVICE LAYER USAGE

### ACL Service

**File**: `~/flext/flext-ldif/src/flext_ldif/services/acl.py`

**Method**: `parse()`

