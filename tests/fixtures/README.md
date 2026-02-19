# LDIF Fixture Documentation


<!-- TOC START -->
- [Overview](#overview)
- [Fixture Sources and Licensing](#fixture-sources-and-licensing)
  - [RFC Fixtures](#rfc-fixtures)
  - [OID/OUD Fixtures](#oidoud-fixtures)
  - [OpenLDAP 2 Fixtures](#openldap-2-fixtures)
- [Using Fixtures in Tests](#using-fixtures-in-tests)
  - [Loading Fixtures](#loading-fixtures)
  - [Running Tests with Fixtures](#running-tests-with-fixtures)
  - [Pytest Markers](#pytest-markers)
- [Helper Utilities](#helper-utilities)
  - [Extract Schema Elements](#extract-schema-elements)
  - [Validate Fixtures](#validate-fixtures)
- [Example Test Pattern](#example-test-pattern)
- [Fixture Content](#fixture-content)
- [Best Practices](#best-practices)
- [Fixture Validation](#fixture-validation)
<!-- TOC END -->

Comprehensive fixture collection for LDAP server testing and quirks validation.

## Overview

This directory contains LDIF fixtures for 4 primary LDAP server types:

- **RFC**: RFC 2252/2256/4519 standard LDAP schema (baseline)
- **OID**: Oracle Internet Directory
- **OUD**: Oracle Unified Directory
- **OpenLDAP 2**: OpenLDAP 2.x

Each server has 4 types of fixtures:

1. **Schema** - LDAP schema definitions (attributeTypes, objectClasses)
2. **Entries** - Example LDAP directory entries
3. **ACL** - Access control configurations
4. **Integration** - Complete directory structures for integration testing

## Fixture Sources and Licensing

### RFC Fixtures

- **Source**: RFC 2252, 2256, 4519 (public domain)
- **License**: Public domain

### OID/OUD Fixtures

- **Source**: Oracle documentation and standards
- **License**: Used for reference and testing

### OpenLDAP 2 Fixtures

- **Source**: OpenLDAP project (<http://www.openldap.org/>)
- **License**: OpenLDAP Public License (BSD-like)

## Using Fixtures in Tests

### Loading Fixtures

```python
from tests.fixtures.loader import FlextLdifFixtures

loader = FlextLdifFixtures.Loader()
schema = loader.load(
    FlextLdifFixtures.ServerType.OID,
    FlextLdifFixtures.FixtureType.SCHEMA
)
```

### Running Tests with Fixtures

```bash
# Run all fixture-based tests
pytest -m fixtures tests/unit/quirks/

# Run operational tests
pytest -m operational tests/unit/quirks/

# Run with specific markers
pytest -m "operational and real_data" tests/unit/quirks/
```

### Pytest Markers

Available markers:

- `fixtures` - Tests using LDIF fixtures
- `operational` - Operational tests with real data
- `real_data` - Tests using real fixture data
- `conversion` - Conversion operation tests
- `roundtrip` - Bidirectional conversion tests
- `quirks` - LDAP server quirks tests

## Helper Utilities

### Extract Schema Elements

```python
from tests.fixtures import helpers

attributes = helpers.extract_attributes(schema_content)
objectclasses = helpers.extract_objectclasses(schema_content)
oid = helpers.extract_oid(attr_definition)
name = helpers.extract_name(attr_definition)
```

### Validate Fixtures

```python
from tests.fixtures.validator import FixtureValidator

validator = FixtureValidator()
result = validator.validate_schema_fixture(content)
if result.is_success:
    stats = result.unwrap()
    print(f"Found {stats['attribute_count']} attributes")
```

## Example Test Pattern

```python
@pytest.mark.parametrize("attr_index", range(10))
def test_parse_real_attributes(oid_schema_attributes, attr_index):
    """Test parsing multiple real attributes from fixtures."""
    if attr_index >= len(oid_schema_attributes):
        pytest.skip("Not enough attributes")

    attr = oid_schema_attributes[attr_index]
    result = quirk.parse_attribute(attr)
    assert result.is_success
```

## Fixture Content

- **RFC Schema**: 40+ attributes, 14+ objectClasses
- **OID Schema**: Oracle-specific schema extensions
- **OUD Schema**: OUD compatibility patterns
- **OpenLDAP 2**: Core + Internet schema (RFC-based)

Each includes realistic entry structures and ACL configurations.

## Best Practices

1. Always validate fixtures before using in tests
2. Use real fixture data for comprehensive testing
3. Test conversion roundtrips
4. Parametrize tests to test all fixture data
5. Preserve semantic equivalence when testing conversions

## Fixture Validation

Run fixture coverage report:

```python
from tests.fixtures.validator import FixtureCoverageReport

coverage = FixtureCoverageReport.generate_summary(all_fixtures)
FixtureCoverageReport.print_coverage_report(coverage)
```

See `conftest.py` for pytest fixture configuration and available fixtures.
