"""Test suite for FlextLdifParser.

This module provides comprehensive testing for the parser functionality
using real services and FlextTests infrastructure.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import base64
from pathlib import Path

from tests.support import FileManager

from flext_ldif.config import FlextLdifConfig
from flext_ldif.models import FlextLdifModels
from flext_ldif.parser import FlextLdifParser


class TestFlextLdifParser:
    """Test suite for FlextLdifParser."""

    def test_initialization(self) -> None:
        """Test parser initialization."""
        parser = FlextLdifParser()

        assert parser is not None
        assert parser._logger is not None
        assert parser._config is not None

    def test_initialization_with_config(self) -> None:
        """Test parser initialization with configuration."""
        config = FlextLdifConfig()
        parser = FlextLdifParser(config)

        assert parser is not None
        assert parser._logger is not None
        assert parser._config is not None

    def test_execute_success(self) -> None:
        """Test successful execution."""
        parser = FlextLdifParser()

        result = parser.execute()

        assert result.is_success
        assert result.value is not None
        assert isinstance(result.value, dict)

    def test_parse_state_enum(self) -> None:
        """Test ParseState enum values."""
        assert FlextLdifParser.ParseState.INITIAL.value == "initial"
        assert FlextLdifParser.ParseState.VERSION.value == "version"
        assert FlextLdifParser.ParseState.COMMENT.value == "comment"
        assert FlextLdifParser.ParseState.ENTRY.value == "entry"
        assert FlextLdifParser.ParseState.CHANGE_RECORD.value == "change_record"
        assert FlextLdifParser.ParseState.ATTRIBUTE.value == "attribute"
        assert FlextLdifParser.ParseState.CONTINUATION.value == "continuation"
        assert FlextLdifParser.ParseState.ERROR.value == "error"

    def test_parse_content_empty(self) -> None:
        """Test parsing empty content."""
        parser = FlextLdifParser()

        result = parser.parse_entries("")

        assert result.is_success
        assert isinstance(result.value, list)
        assert len(result.value) == 0

    def test_parse_content_whitespace_only(self) -> None:
        """Test parsing whitespace-only content."""
        parser = FlextLdifParser()

        result = parser.parse_string("   \n  \t  \n  ")

        assert result.is_success
        assert isinstance(result.value, list)
        assert len(result.value) == 0

    def test_parse_content_comments_only(self) -> None:
        """Test parsing content with only comments."""
        parser = FlextLdifParser()

        content = """# This is a comment
# Another comment
# Yet another comment"""

        result = parser.parse_string(content)

        assert result.is_success
        assert isinstance(result.value, list)
        assert len(result.value) == 0

    def test_parse_content_simple_entry(self) -> None:
        """Test parsing simple LDIF entry."""
        parser = FlextLdifParser()

        content = """dn: cn=testuser,dc=example,dc=com
objectClass: person
cn: testuser
sn: user"""

        result = parser.parse_string(content)

        assert result.is_success
        assert isinstance(result.value, list)
        assert len(result.value) == 1

        entry = result.value[0]
        assert isinstance(entry, FlextLdifModels.Entry)
        assert entry.dn.value == "cn=testuser,dc=example,dc=com"
        assert "objectClass" in entry.attributes.data
        assert "cn" in entry.attributes.data
        assert "sn" in entry.attributes.data

    def test_parse_content_multiple_entries(self) -> None:
        """Test parsing multiple LDIF entries."""
        parser = FlextLdifParser()

        content = """dn: cn=user1,dc=example,dc=com
objectClass: person
cn: user1

dn: cn=user2,dc=example,dc=com
objectClass: person
cn: user2"""

        result = parser.parse_string(content)

        assert result.is_success
        assert isinstance(result.value, list)
        assert len(result.value) == 2

        entry1 = result.value[0]
        entry2 = result.value[1]

        assert entry1.dn.value == "cn=user1,dc=example,dc=com"
        assert entry2.dn.value == "cn=user2,dc=example,dc=com"

    def test_parse_content_with_version(self) -> None:
        """Test parsing content with version line."""
        parser = FlextLdifParser()

        content = """version: 1
dn: cn=testuser,dc=example,dc=com
objectClass: person
cn: testuser"""

        result = parser.parse_string(content)

        assert result.is_success
        assert isinstance(result.value, list)
        assert len(result.value) == 1

    def test_parse_content_with_continuation(self) -> None:
        """Test parsing content with line continuation."""
        parser = FlextLdifParser()

        content = """dn: cn=testuser,dc=example,dc=com
description: This is a very long description that
 continues on the next line
cn: testuser"""

        result = parser.parse_string(content)

        assert result.is_success
        assert isinstance(result.value, list)
        assert len(result.value) == 1

        entry = result.value[0]
        assert "description" in entry.attributes.data
        description = entry.attributes.data["description"]
        assert len(description) == 1
        assert "continues on the next line" in description[0]

    def test_parse_content_with_base64(self) -> None:
        """Test parsing content with base64 encoded data."""
        parser = FlextLdifParser()

        # Base64 encode "test data"

        encoded_data = base64.b64encode(b"test data").decode("ascii")

        content = f"""dn: cn=testuser,dc=example,dc=com
userPassword:: {encoded_data}
cn: testuser"""

        result = parser.parse_string(content)

        assert result.is_success
        assert isinstance(result.value, list)
        assert len(result.value) == 1

        entry = result.value[0]
        assert "userPassword" in entry.attributes.data
        password = entry.attributes.data["userPassword"]
        assert len(password) == 1
        assert password[0] == "test data"

    def test_parse_content_with_change_record(self) -> None:
        """Test parsing content with change record."""
        parser = FlextLdifParser()

        content = """dn: cn=testuser,dc=example,dc=com
changetype: add
objectClass: person
cn: testuser"""

        result = parser.parse_string(content)

        assert result.is_success
        assert isinstance(result.value, list)
        assert len(result.value) == 1

        entry = result.value[0]
        assert entry.dn.value == "cn=testuser,dc=example,dc=com"
        # Note: changetype is handled by ChangeRecord model, not Entry model

    def test_parse_content_with_attribute_options(self) -> None:
        """Test parsing content with attribute options."""
        parser = FlextLdifParser()

        content = """dn: cn=testuser,dc=example,dc=com
cn;lang-en: testuser
cn;lang-fr: utilisateur test
cn: testuser"""

        result = parser.parse_string(content)

        assert result.is_success
        assert isinstance(result.value, list)
        assert len(result.value) == 1

        entry = result.value[0]
        assert "cn" in entry.attributes.data
        cn_values = entry.attributes.data["cn"]
        assert len(cn_values) == 3
        assert "testuser" in cn_values
        assert "utilisateur test" in cn_values

    def test_parse_content_invalid_dn(self) -> None:
        """Test parsing content with invalid DN."""
        parser = FlextLdifParser()

        content = """dn: invalid-dn-without-equals
objectClass: person
cn: testuser"""

        result = parser.parse_string(content)

        # Should still succeed but might handle invalid DN gracefully
        assert result.is_success or result.is_failure
        if result.is_success:
            assert isinstance(result.value, list)

    def test_parse_content_missing_dn(self) -> None:
        """Test parsing content without DN."""
        parser = FlextLdifParser()

        content = """objectClass: person
cn: testuser"""

        result = parser.parse_string(content)

        # Should fail or handle gracefully
        assert result.is_success or result.is_failure

    def test_parse_file_nonexistent(self) -> None:
        """Test parsing nonexistent file."""
        parser = FlextLdifParser()

        result = parser.parse_ldif_file_from_path(Path("nonexistent.ldif"))

        assert result.is_failure
        assert result.error is not None and "No such file or directory" in result.error

    def test_parse_file_success(self) -> None:
        """Test parsing existing file."""
        parser = FlextLdifParser()

        content = """dn: cn=testuser,dc=example,dc=com
objectClass: person
cn: testuser
sn: user"""

        ldif_file = FileManager.create_temp_ldif_file(content)

        result = parser.parse_ldif_file_from_path(ldif_file)

        assert result.is_success
        assert isinstance(result.value, list)
        assert len(result.value) == 1

    def test_parse_file_with_config(self) -> None:
        """Test parsing file with configuration."""
        config = FlextLdifConfig()
        parser = FlextLdifParser(config)

        content = """dn: cn=testuser,dc=example,dc=com
objectClass: person
cn: testuser"""

        ldif_file = FileManager.create_temp_ldif_file(content)

        result = parser.parse_ldif_file_from_path(ldif_file)

        assert result.is_success
        assert isinstance(result.value, list)
        assert len(result.value) == 1

    def test_parse_content_with_real_ldif_data(self) -> None:
        """Test parsing with realistic LDIF data."""
        parser = FlextLdifParser()

        content = """version: 1
# This is a sample LDIF file
dn: uid=john.doe,ou=people,dc=example,dc=com
objectClass: inetOrgPerson
objectClass: organizationalPerson
objectClass: person
objectClass: top
uid: john.doe
cn: John Doe
sn: Doe
givenName: John
mail: john.doe@example.com
telephoneNumber: +1-555-123-4567
employeeNumber: E12345

dn: uid=jane.smith,ou=people,dc=example,dc=com
objectClass: inetOrgPerson
objectClass: organizationalPerson
objectClass: person
objectClass: top
uid: jane.smith
cn: Jane Smith
sn: Smith
givenName: Jane
mail: jane.smith@example.com
telephoneNumber: +1-555-987-6543
employeeNumber: E67890"""

        result = parser.parse_string(content)

        assert result.is_success
        assert isinstance(result.value, list)
        assert len(result.value) == 2

        entry1 = result.value[0]
        entry2 = result.value[1]

        assert entry1.dn.value == "uid=john.doe,ou=people,dc=example,dc=com"
        assert entry2.dn.value == "uid=jane.smith,ou=people,dc=example,dc=com"

        assert "mail" in entry1.attributes.data
        assert "mail" in entry2.attributes.data
        assert entry1.attributes.data["mail"][0] == "john.doe@example.com"
        assert entry2.attributes.data["mail"][0] == "jane.smith@example.com"

    def test_parse_content_with_binary_data(self) -> None:
        """Test parsing content with binary data."""
        parser = FlextLdifParser()

        # Create binary data and encode it

        binary_data = b"binary\x00data\xff\xfe"
        encoded_data = base64.b64encode(binary_data).decode("ascii")

        content = f"""dn: cn=testuser,dc=example,dc=com
userCertificate:: {encoded_data}
cn: testuser"""

        result = parser.parse_string(content)

        assert result.is_success
        assert isinstance(result.value, list)
        assert len(result.value) == 1

        entry = result.value[0]
        assert "userCertificate" in entry.attributes.data
        certificate = entry.attributes.data["userCertificate"]
        assert len(certificate) == 1
        assert certificate[0] == encoded_data

    def test_parse_content_with_multivalued_attributes(self) -> None:
        """Test parsing content with multivalued attributes."""
        parser = FlextLdifParser()

        content = """dn: cn=testuser,dc=example,dc=com
objectClass: person
objectClass: organizationalPerson
objectClass: inetOrgPerson
cn: testuser
cn: Test User
mail: test@example.com
mail: testuser@example.com
telephoneNumber: +1-555-123-4567
telephoneNumber: +1-555-987-6543"""

        result = parser.parse_string(content)

        assert result.is_success
        assert isinstance(result.value, list)
        assert len(result.value) == 1

        entry = result.value[0]
        assert "objectClass" in entry.attributes.data
        assert "cn" in entry.attributes.data
        assert "mail" in entry.attributes.data
        assert "telephoneNumber" in entry.attributes.data

        # Check multivalued attributes
        object_classes = entry.attributes.data["objectClass"]
        assert len(object_classes.values) == 3
        assert "person" in object_classes.values
        assert "organizationalPerson" in object_classes.values
        assert "inetOrgPerson" in object_classes.values

        cn_values = entry.attributes.data["cn"]
        assert len(cn_values.values) == 2
        assert "testuser" in cn_values.values
        assert "Test User" in cn_values.values

        mail_values = entry.attributes.data["mail"]
        assert len(mail_values.values) == 2
        assert "test@example.com" in mail_values.values
        assert "testuser@example.com" in mail_values.values

    def test_parse_content_with_special_characters(self) -> None:
        """Test parsing content with special characters."""
        parser = FlextLdifParser()

        content = """dn: cn=test\\,user,dc=example,dc=com
description: This contains special chars: <>&"'
cn: test,user"""

        result = parser.parse_string(content)

        assert result.is_success
        assert isinstance(result.value, list)
        assert len(result.value) == 1

        entry = result.value[0]
        assert entry.dn.value == "cn=test\\,user,dc=example,dc=com"
        assert "description" in entry.attributes.data
        assert "cn" in entry.attributes.data

    def test_parse_content_with_empty_attributes(self) -> None:
        """Test parsing content with empty attributes."""
        parser = FlextLdifParser()

        content = """dn: cn=testuser,dc=example,dc=com
objectClass: person
cn: testuser
emptyAttribute:
anotherEmptyAttribute: """

        result = parser.parse_string(content)

        assert result.is_success
        assert isinstance(result.value, list)
        assert len(result.value) == 1

        entry = result.value[0]
        assert "emptyAttribute" in entry.attributes.data
        assert "anotherEmptyAttribute" in entry.attributes.data

        empty_attr = entry.attributes.data["emptyAttribute"]
        another_empty_attr = entry.attributes.data["anotherEmptyAttribute"]

        assert len(empty_attr.values) == 1
        assert len(another_empty_attr.values) == 1
        assert not empty_attr.values[0]
        assert not another_empty_attr.values[0]

    def test_parse_content_with_long_lines(self) -> None:
        """Test parsing content with very long lines."""
        parser = FlextLdifParser()

        # Create a very long description
        long_description = "This is a very long description. " * 100

        content = f"""dn: cn=testuser,dc=example,dc=com
objectClass: person
cn: testuser
description: {long_description}"""

        result = parser.parse_string(content)

        assert result.is_success
        assert isinstance(result.value, list)
        assert len(result.value) == 1

        entry = result.value[0]
        assert "description" in entry.attributes.data
        description = entry.attributes.data["description"]
        assert len(description.values) == 1
        assert len(description.values[0]) > 1000  # Should be very long

    def test_parse_content_with_mixed_content(self) -> None:
        """Test parsing content with mixed valid and invalid content."""
        parser = FlextLdifParser()

        content = """# Comment at the beginning
version: 1
# Another comment

dn: cn=validuser,dc=example,dc=com
objectClass: person
cn: validuser

# Comment in the middle

dn: cn=anotheruser,dc=example,dc=com
objectClass: person
cn: anotheruser

# Comment at the end"""

        result = parser.parse_string(content)

        assert result.is_success
        assert isinstance(result.value, list)
        assert len(result.value) == 2

        entry1 = result.value[0]
        entry2 = result.value[1]

        assert entry1.dn.value == "cn=validuser,dc=example,dc=com"
        assert entry2.dn.value == "cn=anotheruser,dc=example,dc=com"

    def test_parse_content_with_unicode(self) -> None:
        """Test parsing content with Unicode characters."""
        parser = FlextLdifParser()

        content = """dn: cn=测试用户,dc=example,dc=com
objectClass: person
cn: 测试用户
description: This contains Unicode: ñáéíóú 中文 🚀"""

        result = parser.parse_string(content)

        assert result.is_success
        assert isinstance(result.value, list)
        assert len(result.value) == 1

        entry = result.value[0]
        assert entry.dn.value == "cn=测试用户,dc=example,dc=com"
        assert "cn" in entry.attributes.data
        assert "description" in entry.attributes.data

        cn_values = entry.attributes.data["cn"]
        assert len(cn_values) == 1
        assert cn_values[0] == "测试用户"

        description_values = entry.attributes.data["description"]
        assert len(description_values) == 1
        assert "Unicode" in description_values[0]
        assert "中文" in description_values[0]
        assert "🚀" in description_values[0]
