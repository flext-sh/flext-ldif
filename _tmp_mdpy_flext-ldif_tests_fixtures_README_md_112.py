# from flext-ldif_tests/fixtures/README.md:112
from tests import FixtureValidator

validator = FixtureValidator()
result = validator.validate_schema_fixture(content)
if result.is_success:
    stats = result.unwrap()
    u.Cli.print(f"Found {stats['attribute_count']} attributes")
