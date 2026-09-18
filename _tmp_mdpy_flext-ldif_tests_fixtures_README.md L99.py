# from flext-ldif/tests/fixtures/README.md:99
from tests import helpers

attributes = helpers.extract_attributes(schema_content)
objectclasses = helpers.extract_objectclasses(schema_content)
oid = helpers.extract_oid(attr_definition)
name = helpers.extract_name(attr_definition)
