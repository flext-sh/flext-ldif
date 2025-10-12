# FLEXT LDIF Test Fixtures

Generic fixture loading infrastructure for LDAP server quirks testing following FLEXT architectural patterns.

## Overview

The `FlextLdifFixtures` class provides standardized access to test fixtures for different LDAP server types. Each server has fixtures for:

- **Schema**: LDAP schema definitions
- **ACL**: Access control lists and permissions
- **Entries**: User/group entries
- **Integration**: Complete directory structure with real quirks

## Supported Servers

- **OID** (Oracle Internet Directory) - ✅ Full fixtures available
- **OUD** (Oracle Unified Directory) - Ready for fixtures
- **OpenLDAP** - Ready for fixtures
- **OpenLDAP1** - Ready for fixtures
- **DS389** (389 Directory Server) - Ready for fixtures
- **Apache Directory** - Ready for fixtures
- **Novell eDirectory** - Ready for fixtures
- **Tivoli** - Ready for fixtures
- **AD** (Active Directory) - Ready for fixtures

## Usage

### 1. Generic Loader (All Servers)

```python
from tests.fixtures import FlextLdifFixtures

# Create generic loader
loader = FlextLdifFixtures.Loader()

# Load specific fixture
oid_schema = loader.load(
    FlextLdifFixtures.ServerType.OID,
    FlextLdifFixtures.FixtureType.SCHEMA
)

# Load all fixtures for a server
all_oid_fixtures = loader.load_all(FlextLdifFixtures.ServerType.OID)

# Get metadata
metadata = loader.get_metadata(
    FlextLdifFixtures.ServerType.OID,
    FlextLdifFixtures.FixtureType.SCHEMA
)
print(f"Entries: {metadata.entry_count}, Lines: {metadata.line_count}")

# Check availability
if loader.fixture_exists(FlextLdifFixtures.ServerType.OID, FlextLdifFixtures.FixtureType.SCHEMA):
    schema = loader.load(FlextLdifFixtures.ServerType.OID, FlextLdifFixtures.FixtureType.SCHEMA)
```

### 2. Server-Specific Loaders (Convenience)

```python
from tests.fixtures import FlextLdifFixtures

# Oracle Internet Directory
oid = FlextLdifFixtures.OID()
schema = oid.schema()
acl = oid.acl()
entries = oid.entries()
integration = oid.integration()
all_fixtures = oid.all()

# Oracle Unified Directory
oud = FlextLdifFixtures.OUD()
schema = oud.schema()

# OpenLDAP
openldap = FlextLdifFixtures.OpenLDAP()
schema = openldap.schema()
```

### 3. Pytest Fixtures

```python
# Test using pytest fixtures
def test_oid_schema(oid_schema: str):
    """Test with pre-loaded OID schema."""
    assert "orclUser" in oid_schema

def test_oid_fixtures(oid_fixtures: FlextLdifFixtures.OID):
    """Test with OID fixture loader."""
    schema = oid_fixtures.schema()
    metadata = oid_fixtures.metadata(FlextLdifFixtures.FixtureType.SCHEMA)
    assert metadata.entry_count > 0

def test_generic_loader(fixtures_loader: FlextLdifFixtures.Loader):
    """Test with generic loader."""
    servers = fixtures_loader.get_available_servers()
    assert FlextLdifFixtures.ServerType.OID in servers
```

### Available Pytest Fixtures

- `fixtures_loader` - Generic loader for all servers
- `oid_fixtures` - OID-specific loader
- `oid_schema` - Pre-loaded OID schema content
- `oid_acl` - Pre-loaded OID ACL content
- `oid_entries` - Pre-loaded OID entries content
- `oid_integration` - Pre-loaded OID integration content
- `oud_fixtures` - OUD-specific loader
- `openldap_fixtures` - OpenLDAP-specific loader

## Directory Structure

```
tests/fixtures/
├── __init__.py           # Main exports
├── loader.py             # FlextLdifFixtures class
├── README.md             # This file
└── oid/                  # Oracle Internet Directory fixtures
    ├── oid_schema_fixtures.ldif
    ├── oid_acl_fixtures.ldif
    ├── oid_entries_fixtures.ldif
    └── oid_integration_fixtures.ldif
```

## OID Fixtures Content

### oid_schema_fixtures.ldif

Oracle OID schema definitions including:

- Oracle namespace attributes (2.16.840.1.113894.\*)
- Custom application attributes
- Oracle objectClasses (orclUser, orclGroup, orclContainer)
- DAS configuration classes

### oid_acl_fixtures.ldif

Oracle OID ACL patterns including:

- orclaci (standard ACL)
- orclentrylevelaci (entry-level ACL)
- BindMode restrictions
- guidattr and dnattr patterns
- Filter-based ACLs
- Complex permission scenarios

### oid_entries_fixtures.ldif

Anonymized OID entries including:

- Users with various password hash types
- Groups with different objectClass variations
- Binary attributes and base64 encoding
- Special characters and escaped DNs
- Multi-valued attributes
- Operational attributes

### oid_integration_fixtures.ldif

**24 Real OID Quirks** from actual client-a export:

1. Mixed case objectClass (groupofuniquenames, inetorgperson)
2. Mixed case orclContainer variations
3. Inconsistent DN spacing
4. Spaces before commas in ACL permissions
5. Real custom attributes (empresa, cpf, contrato, responsavel, calid, vantiveid)
6. Real organizational structure (ou=temporario, ou=associado, ou=estagiario)
7. orclcontainerOC vs orclcontainerOc variations
8. Complex ACL with BindMode
9. Multi-line ACL with guidattr
10. dnattr ACL patterns
11. Filter-based ACL with objectClass
12. Regex DN patterns in ACL
13. groupattr and dnattr combined
14. ACL with none permissions
15. Complex dnattr permissions
16. Group names with ampersands and spaces
17. Mixed case in ACL group references
18. orclACPGroup case variations
19. DAS configuration with language tags
20. Operation URLs container
21. Group with multiple uniquemember references
22. OracleSchemaVersion entry
23. OIDSC configuration
24. noproxy permission

## Adding New Server Fixtures

To add fixtures for a new server type:

1. Create directory: `tests/fixtures/{server_name}/`
2. Add fixture files following naming convention:
   - `{server_name}_schema_fixtures.ldif`
   - `{server_name}_acl_fixtures.ldif`
   - `{server_name}_entries_fixtures.ldif`
   - `{server_name}_integration_fixtures.ldif`
3. Server will be automatically available via generic loader
4. Optionally add server-specific convenience class in `loader.py`

## Best Practices

1. **Use Real Data**: Base fixtures on actual server exports (anonymized)
2. **Document Quirks**: Comment why specific patterns exist
3. **Test Coverage**: Ensure fixtures cover edge cases
4. **Consistency**: Follow naming conventions for easy discovery
5. **Metadata**: Use `get_metadata()` to understand fixture characteristics

## References

- OID Fixtures based on: `~/flext/client-a-oud-mig/data/input/`
- Personal and company names anonymized
- Real quirks preserved for testing compatibility

---

**Copyright (c) 2025 FLEXT Team. All rights reserved.**
**SPDX-License-Identifier: MIT**
