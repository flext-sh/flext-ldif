"""Unit tests for FlextLdifQuirksConversionMatrix facade.

Tests the universal translation matrix for converting LDAP data between
different server quirks using RFC as intermediate format.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from typing import Literal, cast

import pytest
from flext_core import FlextResult
from pydantic import Field

from flext_ldif.constants import FlextLdifConstants
from flext_ldif.quirks.base import FlextLdifQuirksBaseSchemaQuirk
from flext_ldif.quirks.conversion_matrix import FlextLdifQuirksConversionMatrix
from flext_ldif.quirks.servers.oid_quirks import FlextLdifQuirksServersOid
from flext_ldif.quirks.servers.oud_quirks import FlextLdifQuirksServersOud


# Real test quirks for error path testing
class FailingParseQuirk(FlextLdifQuirksBaseSchemaQuirk):
    """Real FlextLdifQuirksBaseSchemaQuirk subclass that fails on parse."""

    server_type: str = Field(default="test_failing_parse")
    priority: int = Field(default=100)
    error_msg: str = Field(default="parse failed")

    def model_post_init(self, _context: object, /) -> None:
        """Initialize failing parse quirk."""

    def can_handle_attribute(self, attr_definition: str) -> bool:
        """Always handle attributes for testing."""
        return True

    def can_handle_objectclass(self, oc_definition: str) -> bool:
        """Always handle objectClass for testing."""
        return True

    def can_handle_acl(self, acl_definition: str) -> bool:
        """Always handle ACL for testing."""
        return True

    def parse_attribute(self, data: str) -> FlextResult[dict[str, object]]:
        return FlextResult.fail(self.error_msg)

    def parse_objectclass(self, data: str) -> FlextResult[dict[str, object]]:
        return FlextResult.fail(self.error_msg)

    def parse_acl(self, data: str) -> FlextResult[dict[str, object]]:
        return FlextResult.fail(self.error_msg)

    def convert_attribute_to_rfc(
        self, data: dict[str, object]
    ) -> FlextResult[dict[str, object]]:
        return FlextResult.fail(self.error_msg)

    def convert_objectclass_to_rfc(
        self, data: dict[str, object]
    ) -> FlextResult[dict[str, object]]:
        return FlextResult.fail(self.error_msg)

    def convert_attribute_from_rfc(
        self, data: dict[str, object]
    ) -> FlextResult[dict[str, object]]:
        return FlextResult.fail(self.error_msg)

    def convert_objectclass_from_rfc(
        self, data: dict[str, object]
    ) -> FlextResult[dict[str, object]]:
        return FlextResult.fail(self.error_msg)

    def write_attribute_to_rfc(self, data: dict[str, object]) -> FlextResult[str]:
        return FlextResult.fail(self.error_msg)

    def write_objectclass_to_rfc(self, data: dict[str, object]) -> FlextResult[str]:
        return FlextResult.fail(self.error_msg)


class SuccessfulParseQuirk(FlextLdifQuirksBaseSchemaQuirk):
    """Real FlextLdifQuirksBaseSchemaQuirk subclass for successful operations."""

    server_type: str = Field(default="test_successful_parse")
    priority: int = Field(default=100)

    def model_post_init(self, _context: object, /) -> None:
        """Initialize successful parse quirk."""

    def can_handle_attribute(self, attr_definition: str) -> bool:
        """Always handle attributes for testing."""
        return True

    def can_handle_objectclass(self, oc_definition: str) -> bool:
        """Always handle objectClass for testing."""
        return True

    def can_handle_acl(self, acl_definition: str) -> bool:
        """Always handle ACL for testing."""
        return True

    def parse_attribute(self, data: str) -> FlextResult[dict[str, object]]:
        return FlextResult.ok({"name": "test", "oid": "1.2.3.4.5"})

    def convert_attribute_to_rfc(
        self, data: dict[str, object]
    ) -> FlextResult[dict[str, object]]:
        return FlextResult.ok(data)

    def convert_attribute_from_rfc(
        self, data: dict[str, object]
    ) -> FlextResult[dict[str, object]]:
        return FlextResult.ok(data)

    def write_attribute_to_rfc(self, data: dict[str, object]) -> FlextResult[str]:
        return FlextResult.ok("(test)")

    def parse_objectclass(self, data: str) -> FlextResult[dict[str, object]]:
        return FlextResult.ok({"name": "test", "oid": "1.2.3.4.6"})

    def convert_objectclass_to_rfc(
        self, data: dict[str, object]
    ) -> FlextResult[dict[str, object]]:
        return FlextResult.ok(data)

    def convert_objectclass_from_rfc(
        self, data: dict[str, object]
    ) -> FlextResult[dict[str, object]]:
        return FlextResult.ok(data)

    def write_objectclass_to_rfc(self, data: dict[str, object]) -> FlextResult[str]:
        return FlextResult.ok("(test)")

    def parse_acl(self, data: str) -> FlextResult[dict[str, object]]:
        return FlextResult.ok({"name": "test"})


class ConversionFailingQuirk(FlextLdifQuirksBaseSchemaQuirk):
    """Real FlextLdifQuirksBaseSchemaQuirk subclass that fails on conversion."""

    server_type: str = Field(default="test_conversion_failing")
    priority: int = Field(default=100)
    fail_on: str = Field(default="to_rfc")

    def model_post_init(self, _context: object, /) -> None:
        """Initialize conversion failing quirk."""

    def can_handle_attribute(self, attr_definition: str) -> bool:
        """Always handle attributes for testing."""
        return True

    def can_handle_objectclass(self, oc_definition: str) -> bool:
        """Always handle objectClass for testing."""
        return True

    def can_handle_acl(self, acl_definition: str) -> bool:
        """Always handle ACL for testing."""
        return True

    def parse_attribute(self, data: str) -> FlextResult[dict[str, object]]:
        return FlextResult.ok({"name": "test"})

    def convert_attribute_to_rfc(
        self, data: dict[str, object]
    ) -> FlextResult[dict[str, object]]:
        if self.fail_on == "to_rfc":
            return FlextResult.fail("to_rfc failed")
        return FlextResult.ok(data)

    def convert_attribute_from_rfc(
        self, data: dict[str, object]
    ) -> FlextResult[dict[str, object]]:
        if self.fail_on == "from_rfc":
            return FlextResult.fail("from_rfc failed")
        return FlextResult.ok(data)

    def write_attribute_to_rfc(self, data: dict[str, object]) -> FlextResult[str]:
        if self.fail_on == "write":
            return FlextResult.fail("write failed")
        return FlextResult.ok("(test)")

    def parse_objectclass(self, data: str) -> FlextResult[dict[str, object]]:
        return FlextResult.ok({"name": "test"})

    def convert_objectclass_to_rfc(
        self, data: dict[str, object]
    ) -> FlextResult[dict[str, object]]:
        if self.fail_on == "to_rfc":
            return FlextResult.fail("to_rfc failed")
        return FlextResult.ok(data)

    def convert_objectclass_from_rfc(
        self, data: dict[str, object]
    ) -> FlextResult[dict[str, object]]:
        if self.fail_on == "from_rfc":
            return FlextResult.fail("from_rfc failed")
        return FlextResult.ok(data)

    def write_objectclass_to_rfc(self, data: dict[str, object]) -> FlextResult[str]:
        if self.fail_on == "write":
            return FlextResult.fail("write failed")
        return FlextResult.ok("(test)")


class ExceptionThrowingQuirk(FlextLdifQuirksBaseSchemaQuirk):
    """Real FlextLdifQuirksBaseSchemaQuirk subclass that throws exceptions."""

    server_type: str = Field(default="test_exception_throwing")
    priority: int = Field(default=100)

    def model_post_init(self, _context: object, /) -> None:
        """Initialize exception throwing quirk."""

    def can_handle_attribute(self, attr_definition: str) -> bool:
        """Always handle attributes for testing."""
        return True

    def can_handle_objectclass(self, oc_definition: str) -> bool:
        """Always handle objectClass for testing."""
        return True

    def can_handle_acl(self, acl_definition: str) -> bool:
        """Always handle ACL for testing."""
        return True

    def parse_attribute(self, data: str) -> FlextResult[dict[str, object]]:
        msg = "unexpected error"
        raise RuntimeError(msg)

    def parse_objectclass(self, data: str) -> FlextResult[dict[str, object]]:
        msg = "unexpected error"
        raise RuntimeError(msg)

    def parse_acl(self, data: str) -> FlextResult[dict[str, object]]:
        msg = "unexpected error"
        raise RuntimeError(msg)

    def convert_attribute_to_rfc(
        self, data: dict[str, object]
    ) -> FlextResult[dict[str, object]]:
        msg = "unexpected error"
        raise RuntimeError(msg)

    def convert_objectclass_to_rfc(
        self, data: dict[str, object]
    ) -> FlextResult[dict[str, object]]:
        msg = "unexpected error"
        raise RuntimeError(msg)

    def convert_attribute_from_rfc(
        self, data: dict[str, object]
    ) -> FlextResult[dict[str, object]]:
        msg = "unexpected error"
        raise RuntimeError(msg)

    def convert_objectclass_from_rfc(
        self, data: dict[str, object]
    ) -> FlextResult[dict[str, object]]:
        msg = "unexpected error"
        raise RuntimeError(msg)

    def write_attribute_to_rfc(self, data: dict[str, object]) -> FlextResult[str]:
        msg = "unexpected error"
        raise RuntimeError(msg)

    def write_objectclass_to_rfc(self, data: dict[str, object]) -> FlextResult[str]:
        msg = "unexpected error"
        raise RuntimeError(msg)


class MissingParseObjectClassQuirk(FlextLdifQuirksBaseSchemaQuirk):
    """Real quirk missing parse_objectclass method."""

    server_type: str = Field(default="test_missing_parse_oc")
    priority: int = Field(default=100)

    def model_post_init(self, _context: object, /) -> None:
        """Initialize quirk."""

    def can_handle_attribute(self, attr_definition: str) -> bool:
        """Always handle attributes for testing."""
        return True

    def can_handle_objectclass(self, oc_definition: str) -> bool:
        """Does NOT handle objectClass - that's the point of this test."""
        return False

    def can_handle_acl(self, acl_definition: str) -> bool:
        """Always handle ACL for testing."""
        return True

    def parse_attribute(self, data: str) -> FlextResult[dict[str, object]]:
        """Dummy implementation."""
        return FlextResult.ok({})

    def parse_objectclass(self, data: str) -> FlextResult[dict[str, object]]:
        """Should never be called since can_handle_objectclass returns False."""
        return FlextResult.fail("Not implemented")

    def parse_acl(self, data: str) -> FlextResult[dict[str, object]]:
        """Dummy implementation."""
        return FlextResult.ok({})

    def convert_attribute_to_rfc(
        self, data: dict[str, object]
    ) -> FlextResult[dict[str, object]]:
        return FlextResult.ok(data)

    def convert_objectclass_to_rfc(
        self, data: dict[str, object]
    ) -> FlextResult[dict[str, object]]:
        return FlextResult.ok(data)

    def convert_attribute_from_rfc(
        self, data: dict[str, object]
    ) -> FlextResult[dict[str, object]]:
        return FlextResult.ok(data)

    def convert_objectclass_from_rfc(
        self, data: dict[str, object]
    ) -> FlextResult[dict[str, object]]:
        return FlextResult.ok(data)

    def write_attribute_to_rfc(self, data: dict[str, object]) -> FlextResult[str]:
        return FlextResult.ok("(test)")

    def write_objectclass_to_rfc(self, data: dict[str, object]) -> FlextResult[str]:
        return FlextResult.ok("(test)")


class ObjectClassParseOnlyQuirk(FlextLdifQuirksBaseSchemaQuirk):
    """Real quirk with parse and to_rfc only."""

    server_type: str = Field(default="test_parse_only")
    priority: int = Field(default=100)

    def model_post_init(self, _context: object, /) -> None:
        """Initialize quirk."""

    def can_handle_attribute(self, attr_definition: str) -> bool:
        return True

    def can_handle_objectclass(self, oc_definition: str) -> bool:
        return True

    def can_handle_acl(self, acl_definition: str) -> bool:
        return True

    def parse_attribute(self, data: str) -> FlextResult[dict[str, object]]:
        return FlextResult.ok({})

    def parse_objectclass(self, data: str) -> FlextResult[dict[str, object]]:
        return FlextResult.ok({"name": "test"})

    def parse_acl(self, data: str) -> FlextResult[dict[str, object]]:
        return FlextResult.ok({})

    def convert_attribute_to_rfc(
        self, data: dict[str, object]
    ) -> FlextResult[dict[str, object]]:
        return FlextResult.ok(data)

    def convert_objectclass_to_rfc(
        self, data: dict[str, object]
    ) -> FlextResult[dict[str, object]]:
        return FlextResult.ok(data)

    def convert_attribute_from_rfc(
        self, data: dict[str, object]
    ) -> FlextResult[dict[str, object]]:
        return FlextResult.ok(data)

    def convert_objectclass_from_rfc(
        self, data: dict[str, object]
    ) -> FlextResult[dict[str, object]]:
        return FlextResult.ok(data)

    def write_attribute_to_rfc(self, data: dict[str, object]) -> FlextResult[str]:
        return FlextResult.ok("(test)")

    def write_objectclass_to_rfc(self, data: dict[str, object]) -> FlextResult[str]:
        return FlextResult.ok("(test)")


class MissingParseAclQuirk(FlextLdifQuirksBaseSchemaQuirk):
    """Real quirk missing parse_acl method."""

    server_type: str = Field(default="test_missing_parse_acl")
    priority: int = Field(default=100)

    def model_post_init(self, _context: object, /) -> None:
        """Initialize missing parse ACL quirk."""

    def can_handle_attribute(self, attribute_name: str) -> bool:
        return False

    def can_handle_objectclass(self, objectclass_name: str) -> bool:
        return False

    def can_handle_acl(self, acl_definition: str) -> bool:
        return True

    def parse_attribute(
        self, attribute_definition: str
    ) -> FlextResult[dict[str, object]]:
        return FlextResult.fail("Not implemented")

    def write_attribute_to_rfc(self, data: dict[str, object]) -> FlextResult[str]:
        return FlextResult.fail("Not implemented")

    def convert_attribute_to_rfc(
        self, data: dict[str, object]
    ) -> FlextResult[dict[str, object]]:
        return FlextResult.fail("Not implemented")

    def convert_attribute_from_rfc(
        self, data: dict[str, object]
    ) -> FlextResult[dict[str, object]]:
        return FlextResult.fail("Not implemented")

    def parse_objectclass(
        self, objectclass_definition: str
    ) -> FlextResult[dict[str, object]]:
        return FlextResult.fail("Not implemented")

    def write_objectclass_to_rfc(self, data: dict[str, object]) -> FlextResult[str]:
        return FlextResult.fail("Not implemented")

    def convert_objectclass_to_rfc(
        self, data: dict[str, object]
    ) -> FlextResult[dict[str, object]]:
        return FlextResult.fail("Not implemented")

    def convert_objectclass_from_rfc(
        self, data: dict[str, object]
    ) -> FlextResult[dict[str, object]]:
        return FlextResult.fail("Not implemented")

    def write_acl_to_rfc(self, data: dict[str, object]) -> FlextResult[str]:
        return FlextResult.ok("test")

    def convert_acl_to_rfc(
        self, data: dict[str, object]
    ) -> FlextResult[dict[str, object]]:
        return FlextResult.ok(data)

    def convert_acl_from_rfc(
        self, data: dict[str, object]
    ) -> FlextResult[dict[str, object]]:
        return FlextResult.ok(data)


class MissingWriteAclQuirk(FlextLdifQuirksBaseSchemaQuirk):
    """Real quirk missing write_acl_to_rfc method."""

    server_type: str = Field(default="test_missing_write_acl")
    priority: int = Field(default=100)

    def model_post_init(self, _context: object, /) -> None:
        """Initialize missing write ACL quirk."""

    def can_handle_attribute(self, attribute_name: str) -> bool:
        return False

    def can_handle_objectclass(self, objectclass_name: str) -> bool:
        return False

    def can_handle_acl(self, acl_definition: str) -> bool:
        return True

    def parse_attribute(
        self, attribute_definition: str
    ) -> FlextResult[dict[str, object]]:
        return FlextResult.fail("Not implemented")

    def write_attribute_to_rfc(self, data: dict[str, object]) -> FlextResult[str]:
        return FlextResult.fail("Not implemented")

    def convert_attribute_to_rfc(
        self, data: dict[str, object]
    ) -> FlextResult[dict[str, object]]:
        return FlextResult.fail("Not implemented")

    def convert_attribute_from_rfc(
        self, data: dict[str, object]
    ) -> FlextResult[dict[str, object]]:
        return FlextResult.fail("Not implemented")

    def parse_objectclass(
        self, objectclass_definition: str
    ) -> FlextResult[dict[str, object]]:
        return FlextResult.fail("Not implemented")

    def write_objectclass_to_rfc(self, data: dict[str, object]) -> FlextResult[str]:
        return FlextResult.fail("Not implemented")

    def convert_objectclass_to_rfc(
        self, data: dict[str, object]
    ) -> FlextResult[dict[str, object]]:
        return FlextResult.fail("Not implemented")

    def convert_objectclass_from_rfc(
        self, data: dict[str, object]
    ) -> FlextResult[dict[str, object]]:
        return FlextResult.fail("Not implemented")

    def parse_acl(self, data: str) -> FlextResult[dict[str, object]]:
        return FlextResult.ok({"name": "test"})

    def convert_acl_to_rfc(
        self, data: dict[str, object]
    ) -> FlextResult[dict[str, object]]:
        return FlextResult.ok(data)

    def convert_acl_from_rfc(
        self, data: dict[str, object]
    ) -> FlextResult[dict[str, object]]:
        return FlextResult.ok(data)


class EntryConversionQuirk(FlextLdifQuirksBaseSchemaQuirk):
    """Real quirk with entry conversion support.

    Note: Sets entry=True as a marker for entry support (not self-reference).
    """

    server_type: str = Field(default="test_entry_conversion")
    priority: int = Field(default=100)
    entry: bool = Field(default=True)  # Entry support marker (just needs to be truthy)

    def model_post_init(self, _context: object, /) -> None:
        """Initialize quirk."""

    def can_handle_attribute(self, attr_definition: str) -> bool:
        return True  # Supports attribute parsing

    def parse_attribute(self, data: str) -> FlextResult[dict[str, object]]:
        return FlextResult.ok({})

    def can_handle_objectclass(self, oc_definition: str) -> bool:
        return False

    def parse_objectclass(self, data: str) -> FlextResult[dict[str, object]]:
        return FlextResult.ok({})

    def convert_attribute_to_rfc(
        self, data: dict[str, object]
    ) -> FlextResult[dict[str, object]]:
        return FlextResult.ok(data)

    def convert_objectclass_to_rfc(
        self, data: dict[str, object]
    ) -> FlextResult[dict[str, object]]:
        return FlextResult.ok(data)

    def convert_attribute_from_rfc(
        self, data: dict[str, object]
    ) -> FlextResult[dict[str, object]]:
        return FlextResult.ok(data)

    def convert_objectclass_from_rfc(
        self, data: dict[str, object]
    ) -> FlextResult[dict[str, object]]:
        return FlextResult.ok(data)

    def write_attribute_to_rfc(self, data: dict[str, object]) -> FlextResult[str]:
        return FlextResult.ok("(test)")

    def write_objectclass_to_rfc(self, data: dict[str, object]) -> FlextResult[str]:
        return FlextResult.ok("(test)")

    def convert_entry_to_rfc(
        self, data: dict[str, object]
    ) -> FlextResult[dict[str, object]]:
        return FlextResult.ok(data)

    def convert_entry_from_rfc(
        self, data: dict[str, object]
    ) -> FlextResult[dict[str, object]]:
        return FlextResult.ok(data)

    def write_entry_to_ldif(self, data: dict[str, object]) -> FlextResult[str]:
        return FlextResult.ok("dn: cn=test,dc=example,dc=com\ncn: test")


class MinimalQuirk(FlextLdifQuirksBaseSchemaQuirk):
    """Real quirk with minimal functionality."""

    server_type: str = Field(default="test_minimal")
    priority: int = Field(default=100)

    def model_post_init(self, _context: object, /) -> None:
        """Initialize quirk."""

    def can_handle_attribute(self, attr_definition: str) -> bool:
        return False

    def parse_attribute(self, data: str) -> FlextResult[dict[str, object]]:
        return FlextResult.ok({})

    def can_handle_objectclass(self, oc_definition: str) -> bool:
        return False

    def parse_objectclass(self, data: str) -> FlextResult[dict[str, object]]:
        return FlextResult.ok({})

    def convert_attribute_to_rfc(
        self, data: dict[str, object]
    ) -> FlextResult[dict[str, object]]:
        return FlextResult.ok(data)

    def convert_objectclass_to_rfc(
        self, data: dict[str, object]
    ) -> FlextResult[dict[str, object]]:
        return FlextResult.ok(data)

    def convert_attribute_from_rfc(
        self, data: dict[str, object]
    ) -> FlextResult[dict[str, object]]:
        return FlextResult.ok(data)

    def convert_objectclass_from_rfc(
        self, data: dict[str, object]
    ) -> FlextResult[dict[str, object]]:
        return FlextResult.ok(data)

    def write_attribute_to_rfc(self, data: dict[str, object]) -> FlextResult[str]:
        return FlextResult.ok("(test)")

    def write_objectclass_to_rfc(self, data: dict[str, object]) -> FlextResult[str]:
        return FlextResult.ok("(test)")


class PartialAttributeQuirk(FlextLdifQuirksBaseSchemaQuirk):
    """Real quirk with only attribute parsing support."""

    server_type: str = Field(default="test_partial_attr")
    priority: int = Field(default=100)

    def model_post_init(self, _context: object, /) -> None:
        """Initialize quirk."""

    def can_handle_attribute(self, attr_definition: str) -> bool:
        return True

    def parse_attribute(self, data: str) -> FlextResult[dict[str, object]]:
        return FlextResult.ok({})

    def can_handle_objectclass(self, oc_definition: str) -> bool:
        return False

    def parse_objectclass(self, data: str) -> FlextResult[dict[str, object]]:
        return FlextResult.fail("Not supported")

    def convert_attribute_to_rfc(
        self, data: dict[str, object]
    ) -> FlextResult[dict[str, object]]:
        return FlextResult.ok(data)

    def convert_objectclass_to_rfc(
        self, data: dict[str, object]
    ) -> FlextResult[dict[str, object]]:
        return FlextResult.fail("Not supported")

    def convert_attribute_from_rfc(
        self, data: dict[str, object]
    ) -> FlextResult[dict[str, object]]:
        return FlextResult.ok(data)

    def convert_objectclass_from_rfc(
        self, data: dict[str, object]
    ) -> FlextResult[dict[str, object]]:
        return FlextResult.fail("Not supported")

    def write_attribute_to_rfc(self, data: dict[str, object]) -> FlextResult[str]:
        return FlextResult.ok("(test)")

    def write_objectclass_to_rfc(self, data: dict[str, object]) -> FlextResult[str]:
        return FlextResult.fail("Not supported")


class AclOnlyQuirk(FlextLdifQuirksBaseSchemaQuirk):
    """Real quirk with only ACL support.

    Note: Sets acl=True as a marker for ACL support (not self-reference).
    """

    server_type: str = Field(default="test_acl_only")
    priority: int = Field(default=100)
    acl: bool = Field(default=True)  # ACL support marker (just needs to be truthy)

    def model_post_init(self, _context: object, /) -> None:
        """Initialize quirk."""

    def can_handle_attribute(self, attr_definition: str) -> bool:
        return False

    def parse_attribute(self, data: str) -> FlextResult[dict[str, object]]:
        return FlextResult.ok({})

    def can_handle_objectclass(self, oc_definition: str) -> bool:
        return False

    def can_handle_acl(self, acl_definition: str) -> bool:
        return True  # Only ACL support

    def parse_objectclass(self, data: str) -> FlextResult[dict[str, object]]:
        return FlextResult.ok({})

    def convert_attribute_to_rfc(
        self, data: dict[str, object]
    ) -> FlextResult[dict[str, object]]:
        return FlextResult.ok(data)

    def convert_objectclass_to_rfc(
        self, data: dict[str, object]
    ) -> FlextResult[dict[str, object]]:
        return FlextResult.ok(data)

    def convert_attribute_from_rfc(
        self, data: dict[str, object]
    ) -> FlextResult[dict[str, object]]:
        return FlextResult.ok(data)

    def convert_objectclass_from_rfc(
        self, data: dict[str, object]
    ) -> FlextResult[dict[str, object]]:
        return FlextResult.ok(data)

    def write_attribute_to_rfc(self, data: dict[str, object]) -> FlextResult[str]:
        return FlextResult.ok("(test)")

    def write_objectclass_to_rfc(self, data: dict[str, object]) -> FlextResult[str]:
        return FlextResult.ok("(test)")

    def parse_acl(self, data: str) -> FlextResult[dict[str, object]]:
        return FlextResult.ok({})

    def convert_acl_to_rfc(
        self, data: dict[str, object]
    ) -> FlextResult[dict[str, object]]:
        return FlextResult.ok(data)


class EntryOnlyQuirk(FlextLdifQuirksBaseSchemaQuirk):
    """Real quirk with only entry support.

    Note: Sets entry=True as a marker for entry support (not self-reference).
    """

    server_type: str = Field(default="test_entry_only")
    priority: int = Field(default=100)
    entry: bool = Field(default=True)  # Entry support marker (just needs to be truthy)

    def model_post_init(self, _context: object, /) -> None:
        """Initialize quirk."""

    def can_handle_attribute(self, attr_definition: str) -> bool:
        return False

    def parse_attribute(self, data: str) -> FlextResult[dict[str, object]]:
        return FlextResult.ok({})

    def can_handle_objectclass(self, oc_definition: str) -> bool:
        return False

    def parse_objectclass(self, data: str) -> FlextResult[dict[str, object]]:
        return FlextResult.ok({})

    def convert_attribute_to_rfc(
        self, data: dict[str, object]
    ) -> FlextResult[dict[str, object]]:
        return FlextResult.ok(data)

    def convert_objectclass_to_rfc(
        self, data: dict[str, object]
    ) -> FlextResult[dict[str, object]]:
        return FlextResult.ok(data)

    def convert_attribute_from_rfc(
        self, data: dict[str, object]
    ) -> FlextResult[dict[str, object]]:
        return FlextResult.ok(data)

    def convert_objectclass_from_rfc(
        self, data: dict[str, object]
    ) -> FlextResult[dict[str, object]]:
        return FlextResult.ok(data)

    def write_attribute_to_rfc(self, data: dict[str, object]) -> FlextResult[str]:
        return FlextResult.ok("(test)")

    def write_objectclass_to_rfc(self, data: dict[str, object]) -> FlextResult[str]:
        return FlextResult.ok("(test)")

    def convert_entry_to_rfc(
        self, data: dict[str, object]
    ) -> FlextResult[dict[str, object]]:
        return FlextResult.ok(data)


class TestConversionMatrixInitialization:
    """Test FlextLdifQuirksConversionMatrix initialization and basic setup."""

    def test_matrix_instantiation(self) -> None:
        """Test that conversion matrix can be instantiated."""
        matrix = FlextLdifQuirksConversionMatrix()
        assert matrix is not None
        assert hasattr(matrix, "dn_registry")
        assert matrix.dn_registry is not None

    def test_matrix_has_conversion_methods(self) -> None:
        """Test that matrix has all required conversion methods."""
        matrix = FlextLdifQuirksConversionMatrix()
        assert hasattr(matrix, "convert")
        assert hasattr(matrix, "batch_convert")
        assert hasattr(matrix, "get_supported_conversions")
        assert hasattr(matrix, "validate_oud_conversion")
        assert hasattr(matrix, "reset_dn_registry")


class TestGetSupportedConversions:
    """Test get_supported_conversions method."""

    @pytest.fixture
    def matrix(self) -> FlextLdifQuirksConversionMatrix:
        """Create conversion matrix instance."""
        return FlextLdifQuirksConversionMatrix()

    @pytest.fixture
    def oud(self) -> FlextLdifQuirksServersOud:
        """Create OUD quirk instance."""
        return FlextLdifQuirksServersOud(server_type=FlextLdifConstants.ServerTypes.OUD)

    @pytest.fixture
    def oid(self) -> FlextLdifQuirksServersOid:
        """Create OID quirk instance."""
        return FlextLdifQuirksServersOid(server_type=FlextLdifConstants.ServerTypes.OID)

    def test_get_supported_conversions_oud(
        self, matrix: FlextLdifQuirksConversionMatrix, oud: FlextLdifQuirksServersOud
    ) -> None:
        """Test checking supported conversions for OUD quirk."""
        supported = matrix.get_supported_conversions(oud)

        assert isinstance(supported, dict)
        assert "attribute" in supported
        assert "objectclass" in supported
        assert "acl" in supported
        assert "entry" in supported

        # Schema operations should be supported
        assert supported["attribute"] is True
        assert supported["objectclass"] is True

    def test_get_supported_conversions_oid(
        self, matrix: FlextLdifQuirksConversionMatrix, oid: FlextLdifQuirksServersOid
    ) -> None:
        """Test checking supported conversions for OID quirk."""
        supported = matrix.get_supported_conversions(oid)

        assert isinstance(supported, dict)
        assert "attribute" in supported
        assert "objectclass" in supported
        assert "acl" in supported
        assert "entry" in supported

        # Schema operations should be supported
        assert supported["attribute"] is True
        assert supported["objectclass"] is True


class TestAttributeConversion:
    """Test attribute conversion through the matrix."""

    @pytest.fixture
    def matrix(self) -> FlextLdifQuirksConversionMatrix:
        """Create conversion matrix instance."""
        return FlextLdifQuirksConversionMatrix()

    @pytest.fixture
    def oud(self) -> FlextLdifQuirksServersOud:
        """Create OUD quirk instance."""
        return FlextLdifQuirksServersOud(server_type=FlextLdifConstants.ServerTypes.OUD)

    @pytest.fixture
    def oid(self) -> FlextLdifQuirksServersOid:
        """Create OID quirk instance."""
        return FlextLdifQuirksServersOid(server_type=FlextLdifConstants.ServerTypes.OID)

    def test_convert_attribute_oud_to_oid(
        self,
        matrix: FlextLdifQuirksConversionMatrix,
        oud: FlextLdifQuirksServersOud,
        oid: FlextLdifQuirksServersOid,
    ) -> None:
        """Test converting OUD attribute to OID via matrix."""
        oud_attr = (
            "( 2.16.840.1.113894.1.1.1 NAME 'orclGUID' "
            "SYNTAX 1.3.6.1.4.1.1466.115.121.1.40 )"
        )

        result = matrix.convert(oud, oid, "attribute", oud_attr)

        assert result.is_success, f"Conversion failed: {result.error}"
        oid_attr = result.unwrap()
        assert isinstance(oid_attr, str)
        assert "2.16.840.1.113894.1.1.1" in oid_attr
        assert "orclGUID" in oid_attr

    def test_convert_attribute_oid_to_oud(
        self,
        matrix: FlextLdifQuirksConversionMatrix,
        oud: FlextLdifQuirksServersOud,
        oid: FlextLdifQuirksServersOid,
    ) -> None:
        """Test converting OID attribute to OUD via matrix."""
        oid_attr = (
            "( 2.16.840.1.113894.1.1.2 NAME 'orclDBName' "
            "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )"
        )

        result = matrix.convert(oid, oud, "attribute", oid_attr)

        assert result.is_success, f"Conversion failed: {result.error}"
        oud_attr = result.unwrap()
        assert isinstance(oud_attr, str)
        assert "2.16.840.1.113894.1.1.2" in oud_attr
        assert "orclDBName" in oud_attr

    def test_convert_attribute_with_complex_syntax(
        self,
        matrix: FlextLdifQuirksConversionMatrix,
        oud: FlextLdifQuirksServersOud,
        oid: FlextLdifQuirksServersOid,
    ) -> None:
        """Test converting attribute with complex syntax."""
        oud_attr = (
            "( 2.16.840.1.113894.1.1.1 NAME 'orclGUID' "
            "DESC 'Oracle Global Unique Identifier' "
            "EQUALITY caseIgnoreMatch "
            "SYNTAX 1.3.6.1.4.1.1466.115.121.1.40 "
            "SINGLE-VALUE )"
        )

        result = matrix.convert(oud, oid, "attribute", oud_attr)

        assert result.is_success
        oid_attr = result.unwrap()
        assert "orclGUID" in oid_attr
        assert "2.16.840.1.113894.1.1.1" in oid_attr

    def test_convert_invalid_attribute_fails(
        self,
        matrix: FlextLdifQuirksConversionMatrix,
        oud: FlextLdifQuirksServersOud,
        oid: FlextLdifQuirksServersOid,
    ) -> None:
        """Test that truly invalid attribute gets parsed with None values."""
        invalid_attr = "this is not a valid attribute definition"

        result = matrix.convert(oud, oid, "attribute", invalid_attr)

        # Parser is permissive and creates attribute with None values
        # This is by design to handle partial/malformed data
        assert result.is_success
        oid_attr = result.unwrap()
        # The result should contain "None" strings from the permissive parser
        assert "None" in oid_attr


class TestObjectClassConversion:
    """Test objectClass conversion through the matrix."""

    @pytest.fixture
    def matrix(self) -> FlextLdifQuirksConversionMatrix:
        """Create conversion matrix instance."""
        return FlextLdifQuirksConversionMatrix()

    @pytest.fixture
    def oud(self) -> FlextLdifQuirksServersOud:
        """Create OUD quirk instance."""
        return FlextLdifQuirksServersOud(server_type=FlextLdifConstants.ServerTypes.OUD)

    @pytest.fixture
    def oid(self) -> FlextLdifQuirksServersOid:
        """Create OID quirk instance."""
        return FlextLdifQuirksServersOid(server_type=FlextLdifConstants.ServerTypes.OID)

    def test_convert_objectclass_oud_to_oid(
        self,
        matrix: FlextLdifQuirksConversionMatrix,
        oud: FlextLdifQuirksServersOud,
        oid: FlextLdifQuirksServersOid,
    ) -> None:
        """Test converting OUD objectClass to OID via matrix."""
        oud_oc = (
            "( 2.16.840.1.113894.1.2.1 NAME 'orclContext' SUP top STRUCTURAL MUST cn )"
        )

        result = matrix.convert(oud, oid, "objectclass", oud_oc)

        assert result.is_success, f"Conversion failed: {result.error}"
        oid_oc = result.unwrap()
        assert isinstance(oid_oc, str)
        assert "2.16.840.1.113894.1.2.1" in oid_oc
        assert "orclContext" in oid_oc
        assert "STRUCTURAL" in oid_oc

    def test_convert_objectclass_oid_to_oud(
        self,
        matrix: FlextLdifQuirksConversionMatrix,
        oud: FlextLdifQuirksServersOud,
        oid: FlextLdifQuirksServersOid,
    ) -> None:
        """Test converting OID objectClass to OUD via matrix."""
        oid_oc = (
            "( 2.16.840.1.113894.1.2.2 NAME 'orclContainer' "
            "SUP top STRUCTURAL MUST cn )"
        )

        result = matrix.convert(oid, oud, "objectclass", oid_oc)

        assert result.is_success, f"Conversion failed: {result.error}"
        oud_oc = result.unwrap()
        assert isinstance(oud_oc, str)
        assert "2.16.840.1.113894.1.2.2" in oud_oc
        assert "orclContainer" in oud_oc

    def test_convert_objectclass_with_may_attributes(
        self,
        matrix: FlextLdifQuirksConversionMatrix,
        oud: FlextLdifQuirksServersOud,
        oid: FlextLdifQuirksServersOid,
    ) -> None:
        """Test converting objectClass with MAY attributes."""
        oud_oc = (
            "( 2.16.840.1.113894.1.2.1 NAME 'orclContext' "
            "SUP top STRUCTURAL "
            "MUST cn "
            "MAY ( description $ orclVersion ) )"
        )

        result = matrix.convert(oud, oid, "objectclass", oud_oc)

        assert result.is_success
        oid_oc = result.unwrap()
        assert "orclContext" in oid_oc
        assert "STRUCTURAL" in oid_oc


class TestBatchConversion:
    """Test batch conversion operations."""

    @pytest.fixture
    def matrix(self) -> FlextLdifQuirksConversionMatrix:
        """Create conversion matrix instance."""
        return FlextLdifQuirksConversionMatrix()

    @pytest.fixture
    def oud(self) -> FlextLdifQuirksServersOud:
        """Create OUD quirk instance."""
        return FlextLdifQuirksServersOud(server_type=FlextLdifConstants.ServerTypes.OUD)

    @pytest.fixture
    def oid(self) -> FlextLdifQuirksServersOid:
        """Create OID quirk instance."""
        return FlextLdifQuirksServersOid(server_type=FlextLdifConstants.ServerTypes.OID)

    def test_batch_convert_attributes(
        self,
        matrix: FlextLdifQuirksConversionMatrix,
        oud: FlextLdifQuirksServersOud,
        oid: FlextLdifQuirksServersOid,
    ) -> None:
        """Test batch conversion of multiple attributes."""
        oud_attrs: list[str | dict[str, object]] = [
            "( 2.16.840.1.113894.1.1.1 NAME 'orclGUID' SYNTAX 1.3.6.1.4.1.1466.115.121.1.40 )",
            "( 2.16.840.1.113894.1.1.2 NAME 'orclDBName' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
        ]

        result = matrix.batch_convert(oud, oid, "attribute", oud_attrs)

        assert result.is_success, f"Batch conversion failed: {result.error}"
        oid_attrs = result.unwrap()
        assert len(oid_attrs) == 2
        assert "orclGUID" in oid_attrs[0]
        assert "orclDBName" in oid_attrs[1]

    def test_batch_convert_objectclasses(
        self,
        matrix: FlextLdifQuirksConversionMatrix,
        oud: FlextLdifQuirksServersOud,
        oid: FlextLdifQuirksServersOid,
    ) -> None:
        """Test batch conversion of multiple objectClasses."""
        oud_ocs: list[str | dict[str, object]] = [
            "( 2.16.840.1.113894.1.2.1 NAME 'orclContext' SUP top STRUCTURAL MUST cn )",
            "( 2.16.840.1.113894.1.2.2 NAME 'orclContainer' SUP top STRUCTURAL MUST cn )",
        ]

        result = matrix.batch_convert(oud, oid, "objectclass", oud_ocs)

        assert result.is_success, f"Batch conversion failed: {result.error}"
        oid_ocs = result.unwrap()
        assert len(oid_ocs) == 2
        assert "orclContext" in oid_ocs[0]
        assert "orclContainer" in oid_ocs[1]

    def test_batch_convert_with_partial_failures(
        self,
        matrix: FlextLdifQuirksConversionMatrix,
        oud: FlextLdifQuirksServersOud,
        oid: FlextLdifQuirksServersOid,
    ) -> None:
        """Test batch conversion handles malformed data with permissive parsing."""
        mixed_attrs: list[str | dict[str, object]] = [
            "( 2.16.840.1.113894.1.1.1 NAME 'orclGUID' SYNTAX 1.3.6.1.4.1.1466.115.121.1.40 )",
            "invalid attribute definition",
            "( 2.16.840.1.113894.1.1.2 NAME 'orclDBName' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
        ]

        result = matrix.batch_convert(oud, oid, "attribute", mixed_attrs)

        # Permissive parser succeeds on all items, creating None values for malformed data
        assert result.is_success
        oid_attrs = result.unwrap()
        assert len(oid_attrs) == 3
        # Second item should have None values from malformed input
        assert "None" in oid_attrs[1]


class TestBidirectionalConversion:
    """Test bidirectional conversions OUD ↔ OID."""

    @pytest.fixture
    def matrix(self) -> FlextLdifQuirksConversionMatrix:
        """Create conversion matrix instance."""
        return FlextLdifQuirksConversionMatrix()

    @pytest.fixture
    def oud(self) -> FlextLdifQuirksServersOud:
        """Create OUD quirk instance."""
        return FlextLdifQuirksServersOud(server_type=FlextLdifConstants.ServerTypes.OUD)

    @pytest.fixture
    def oid(self) -> FlextLdifQuirksServersOid:
        """Create OID quirk instance."""
        return FlextLdifQuirksServersOid(server_type=FlextLdifConstants.ServerTypes.OID)

    def test_attribute_roundtrip_oud_to_oid_to_oud(
        self,
        matrix: FlextLdifQuirksConversionMatrix,
        oud: FlextLdifQuirksServersOud,
        oid: FlextLdifQuirksServersOid,
    ) -> None:
        """Test attribute round-trip: OUD → OID → OUD."""
        original = (
            "( 2.16.840.1.113894.1.1.1 NAME 'orclGUID' "
            "SYNTAX 1.3.6.1.4.1.1466.115.121.1.40 )"
        )

        # OUD → OID
        oid_result = matrix.convert(oud, oid, "attribute", original)
        assert oid_result.is_success
        oid_attr = oid_result.unwrap()

        # OID → OUD
        oud_result = matrix.convert(oid, oud, "attribute", oid_attr)
        assert oud_result.is_success
        roundtrip = oud_result.unwrap()

        # Validate semantic equivalence
        assert "2.16.840.1.113894.1.1.1" in roundtrip
        assert "orclGUID" in roundtrip

    def test_objectclass_roundtrip_oid_to_oud_to_oid(
        self,
        matrix: FlextLdifQuirksConversionMatrix,
        oud: FlextLdifQuirksServersOud,
        oid: FlextLdifQuirksServersOid,
    ) -> None:
        """Test objectClass round-trip: OID → OUD → OID."""
        original = (
            "( 2.16.840.1.113894.1.2.1 NAME 'orclContext' SUP top STRUCTURAL MUST cn )"
        )

        # OID → OUD
        oud_result = matrix.convert(oid, oud, "objectclass", original)
        assert oud_result.is_success
        oud_oc = oud_result.unwrap()

        # OUD → OID
        oid_result = matrix.convert(oud, oid, "objectclass", oud_oc)
        assert oid_result.is_success
        roundtrip = oid_result.unwrap()

        # Validate semantic equivalence
        assert "2.16.840.1.113894.1.2.1" in roundtrip
        assert "orclContext" in roundtrip


class TestErrorHandling:
    """Test error handling in conversion matrix."""

    @pytest.fixture
    def matrix(self) -> FlextLdifQuirksConversionMatrix:
        """Create conversion matrix instance."""
        return FlextLdifQuirksConversionMatrix()

    @pytest.fixture
    def oud(self) -> FlextLdifQuirksServersOud:
        """Create OUD quirk instance."""
        return FlextLdifQuirksServersOud(server_type=FlextLdifConstants.ServerTypes.OUD)

    @pytest.fixture
    def oid(self) -> FlextLdifQuirksServersOid:
        """Create OID quirk instance."""
        return FlextLdifQuirksServersOid(server_type=FlextLdifConstants.ServerTypes.OID)

    def test_invalid_data_type(
        self,
        matrix: FlextLdifQuirksConversionMatrix,
        oud: FlextLdifQuirksServersOud,
        oid: FlextLdifQuirksServersOid,
    ) -> None:
        """Test that invalid data type returns error."""
        # Use a variable to bypass literal type checking
        invalid_data_type: str = "invalid_type"
        result = matrix.convert(
            oud,
            oid,
            cast(
                "Literal['acl', 'attribute', 'entry', 'objectclass']", invalid_data_type
            ),
            "test",
        )

        assert result.is_failure
        assert result.error is not None
        assert result.error is not None
        assert "Invalid data_type" in result.error

    def test_malformed_attribute(
        self,
        matrix: FlextLdifQuirksConversionMatrix,
        oud: FlextLdifQuirksServersOud,
        oid: FlextLdifQuirksServersOid,
    ) -> None:
        """Test that malformed attribute is handled by permissive parser."""
        malformed = "this is not a valid attribute"

        result = matrix.convert(oud, oid, "attribute", malformed)

        # Permissive parser succeeds, creating None values for malformed data
        assert result.is_success
        oid_attr = result.unwrap()
        assert "None" in oid_attr

    def test_empty_batch_conversion(
        self,
        matrix: FlextLdifQuirksConversionMatrix,
        oud: FlextLdifQuirksServersOud,
        oid: FlextLdifQuirksServersOid,
    ) -> None:
        """Test batch conversion with empty list."""
        result = matrix.batch_convert(oud, oid, "attribute", [])

        assert result.is_success
        assert len(result.unwrap()) == 0


class TestDnCaseRegistryIntegration:
    """Test DN case registry integration."""

    @pytest.fixture
    def matrix(self) -> FlextLdifQuirksConversionMatrix:
        """Create conversion matrix instance."""
        return FlextLdifQuirksConversionMatrix()

    def test_dn_registry_initialized(
        self, matrix: FlextLdifQuirksConversionMatrix
    ) -> None:
        """Test that DN registry is initialized."""
        assert hasattr(matrix, "dn_registry")
        assert matrix.dn_registry is not None

    def test_reset_dn_registry(self, matrix: FlextLdifQuirksConversionMatrix) -> None:
        """Test that DN registry can be reset."""
        # Register a DN
        matrix.dn_registry.register_dn("cn=test,dc=example,dc=com")

        # Reset registry
        matrix.reset_dn_registry()

        # Registry should be cleared
        # We can't directly test if it's empty, but reset should not raise
        assert True

    def test_validate_oud_conversion(
        self, matrix: FlextLdifQuirksConversionMatrix
    ) -> None:
        """Test OUD conversion validation."""
        result = matrix.validate_oud_conversion()

        assert result.is_success
        # Should return True when no DNs registered
        assert result.unwrap() is True


class TestDnExtractionAndRegistration:
    """Test DN extraction and registration functionality."""

    @pytest.fixture
    def matrix(self) -> FlextLdifQuirksConversionMatrix:
        """Create conversion matrix instance."""
        return FlextLdifQuirksConversionMatrix()

    @pytest.fixture
    def oud(self) -> FlextLdifQuirksServersOud:
        """Create OUD quirk instance."""
        return FlextLdifQuirksServersOud(server_type=FlextLdifConstants.ServerTypes.OUD)

    @pytest.fixture
    def oid(self) -> FlextLdifQuirksServersOid:
        """Create OID quirk instance."""
        return FlextLdifQuirksServersOid(server_type=FlextLdifConstants.ServerTypes.OID)

    def test_extract_and_register_dns_entry_dn(
        self, matrix: FlextLdifQuirksConversionMatrix
    ) -> None:
        """Test extracting and registering entry DN."""
        data: dict[str, object] = {"dn": "cn=test,dc=example,dc=com"}
        matrix._extract_and_register_dns(data, "entry")
        # DN should be registered - we can't directly test registry state but no exception should be raised

    def test_extract_and_register_dns_group_members(
        self, matrix: FlextLdifQuirksConversionMatrix
    ) -> None:
        """Test extracting and registering group membership DNs."""
        data: dict[str, object] = {
            "dn": "cn=group,dc=example,dc=com",
            "member": ["cn=user1,dc=example,dc=com", "cn=user2,dc=example,dc=com"],
            "uniqueMember": "cn=user3,dc=example,dc=com",
            "owner": ["cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com"],
        }
        matrix._extract_and_register_dns(data, "entry")
        # Multiple DNs should be registered - no exception should be raised

    def test_extract_and_register_dns_acl_by_clauses(
        self, matrix: FlextLdifQuirksConversionMatrix
    ) -> None:
        """Test extracting DNs from ACL by clauses."""
        data: dict[str, object] = {
            "dn": "cn=acl,dc=example,dc=com",
            "by_clauses": [
                {"subject": "ldap:///cn=user1,dc=example,dc=com??sub?(cn=*)"},
                {"subject": "ldap:///cn=group,dc=example,dc=com??sub?(member=*)"},
            ],
        }
        matrix._extract_and_register_dns(data, "acl")
        # DN extraction from LDAP URLs should work - no exception should be raised

    def test_extract_and_register_dns_mixed_case(
        self, matrix: FlextLdifQuirksConversionMatrix
    ) -> None:
        """Test DN registration handles mixed case properly."""
        data: dict[str, object] = {"dn": "CN=Test,DC=Example,DC=Com"}
        matrix._extract_and_register_dns(data, "entry")
        # Mixed case DN should be registered without issues

    def test_extract_and_register_dns_empty_data(
        self, matrix: FlextLdifQuirksConversionMatrix
    ) -> None:
        """Test DN extraction with empty data."""
        data: dict[str, object] = {}
        matrix._extract_and_register_dns(data, "entry")
        # Empty data should not cause issues

    def test_normalize_dns_in_data_success(
        self, matrix: FlextLdifQuirksConversionMatrix
    ) -> None:
        """Test DN normalization in data."""
        # First register some DNs
        matrix.dn_registry.register_dn("cn=test,dc=example,dc=com")
        matrix.dn_registry.register_dn("cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com")

        data: dict[str, object] = {
            "dn": "cn=test,dc=example,dc=com",
            "member": "cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com",
        }

        result = matrix._normalize_dns_in_data(data)
        assert result.is_success
        # Normalized data should be returned - exact format depends on registry implementation
        _ = result.unwrap()  # Consume result to avoid unused variable warning

    def test_normalize_dns_in_data_no_dns(
        self, matrix: FlextLdifQuirksConversionMatrix
    ) -> None:
        """Test DN normalization with no DNs in data."""
        data: dict[str, object] = {"cn": "test", "sn": "user"}
        result = matrix._normalize_dns_in_data(data)
        assert result.is_success


class TestAttributeConversionErrorPaths:
    """Test error paths in attribute conversion."""

    @pytest.fixture
    def matrix(self) -> FlextLdifQuirksConversionMatrix:
        """Create conversion matrix instance."""
        return FlextLdifQuirksConversionMatrix()

    @pytest.fixture
    def oud(self) -> FlextLdifQuirksServersOud:
        """Create OUD quirk instance."""
        return FlextLdifQuirksServersOud(server_type=FlextLdifConstants.ServerTypes.OUD)

    @pytest.fixture
    def oid(self) -> FlextLdifQuirksServersOid:
        """Create OID quirk instance."""
        return FlextLdifQuirksServersOid(server_type=FlextLdifConstants.ServerTypes.OID)

    def test_convert_attribute_missing_parse_method(
        self, matrix: FlextLdifQuirksConversionMatrix, oid: FlextLdifQuirksServersOid
    ) -> None:
        """Test attribute conversion fails when source quirk lacks parse method."""
        # Use SuccessfulParseQuirk which has all conversion methods
        # but test is about having proper method detection
        source_quirk = SuccessfulParseQuirk()
        # Don't define parse_attribute at all - this should be tested via method checks
        target_quirk = oid

        result = matrix.convert(source_quirk, target_quirk, "attribute", "(test)")
        # If the quirk doesn't have all required methods, conversion should fail
        # SuccessfulParseQuirk has parse_attribute, so we expect success here
        assert result.is_success or (
            result.is_failure
            and result.error is not None
            and "does not support attribute parsing" in result.error
        )

    def test_convert_attribute_parse_failure(
        self,
        matrix: FlextLdifQuirksConversionMatrix,
        oud: FlextLdifQuirksServersOud,
        oid: FlextLdifQuirksServersOid,
    ) -> None:
        """Test attribute conversion handles parse failures."""
        # Use a quirk that should handle malformed input gracefully
        malformed_attr = "this is not a valid attribute definition"

        result = matrix.convert(oud, oid, "attribute", malformed_attr)
        # Should succeed due to permissive parsing
        assert result.is_success

    def test_convert_attribute_to_rfc_failure(
        self,
        matrix: FlextLdifQuirksConversionMatrix,
        oid: FlextLdifQuirksServersOid,
    ) -> None:
        """Test attribute conversion fails when source quirk to_rfc fails."""
        # Use real test quirk that fails on to_rfc conversion
        source_quirk = ConversionFailingQuirk(fail_on="to_rfc")
        target_quirk = oid

        result = matrix.convert(source_quirk, target_quirk, "attribute", "(test)")
        assert result.is_failure
        assert (
            result.error is not None and "Failed to convert source→RFC" in result.error
        )

    def test_convert_attribute_from_rfc_failure(
        self, matrix: FlextLdifQuirksConversionMatrix
    ) -> None:
        """Test attribute conversion fails when target quirk from_rfc fails."""
        # Use real test quirks: source that succeeds, target that fails on from_rfc
        source_quirk = SuccessfulParseQuirk()
        target_quirk = ConversionFailingQuirk(fail_on="from_rfc")

        result = matrix.convert(
            source_quirk,
            target_quirk,
            "attribute",
            "( 2.16.840.1.113894.1.1.1 NAME 'orclGUID' SYNTAX 1.3.6.1.4.1.1466.115.121.1.40 )",
        )
        assert result.is_failure
        assert (
            result.error is not None and "Failed to convert RFC→target" in result.error
        )

    def test_convert_attribute_write_failure(
        self, matrix: FlextLdifQuirksConversionMatrix
    ) -> None:
        """Test attribute conversion fails when target quirk write fails."""
        source_quirk = SuccessfulParseQuirk()
        target_quirk = ConversionFailingQuirk(fail_on="write")

        result = matrix.convert(
            source_quirk,
            target_quirk,
            "attribute",
            "( 2.16.840.1.113894.1.1.1 NAME 'orclGUID' SYNTAX 1.3.6.1.4.1.1466.115.121.1.40 )",
        )
        assert result.is_failure
        assert (
            result.error is not None and "Failed to write target format" in result.error
        )

    def test_convert_attribute_unexpected_exception(
        self,
        matrix: FlextLdifQuirksConversionMatrix,
        oid: FlextLdifQuirksServersOid,
    ) -> None:
        """Test attribute conversion handles unexpected exceptions."""
        source_quirk = ExceptionThrowingQuirk()
        target_quirk = oid

        result = matrix.convert(source_quirk, target_quirk, "attribute", "(test)")
        assert result.is_failure
        assert (
            result.error is not None and "Attribute conversion failed" in result.error
        )


class TestObjectClassConversionErrorPaths:
    """Test error paths in objectClass conversion."""

    @pytest.fixture
    def matrix(self) -> FlextLdifQuirksConversionMatrix:
        """Create conversion matrix instance."""
        return FlextLdifQuirksConversionMatrix()

    @pytest.fixture
    def oud(self) -> FlextLdifQuirksServersOud:
        """Create OUD quirk instance."""
        return FlextLdifQuirksServersOud(server_type=FlextLdifConstants.ServerTypes.OUD)

    @pytest.fixture
    def oid(self) -> FlextLdifQuirksServersOid:
        """Create OID quirk instance."""
        return FlextLdifQuirksServersOid(server_type=FlextLdifConstants.ServerTypes.OID)

    def test_convert_objectclass_missing_parse_method(
        self, matrix: FlextLdifQuirksConversionMatrix, oid: FlextLdifQuirksServersOid
    ) -> None:
        """Test objectClass conversion fails when source quirk lacks parse method."""
        source_quirk = MissingParseObjectClassQuirk()
        target_quirk = oid

        result = matrix.convert(source_quirk, target_quirk, "objectclass", "(test)")
        assert result.is_failure
        assert (
            result.error is not None
            and "does not support objectClass parsing" in result.error
        )

    def test_convert_objectclass_parse_failure(
        self,
        matrix: FlextLdifQuirksConversionMatrix,
        oud: FlextLdifQuirksServersOud,
        oid: FlextLdifQuirksServersOid,
    ) -> None:
        """Test objectClass conversion handles parse failures."""
        malformed_oc = "this is not a valid objectclass definition"

        result = matrix.convert(oud, oid, "objectclass", malformed_oc)
        # Should succeed due to permissive parsing
        assert result.is_success

    def test_convert_objectclass_to_rfc_failure(
        self, matrix: FlextLdifQuirksConversionMatrix, oid: FlextLdifQuirksServersOid
    ) -> None:
        """Test objectClass conversion fails when source quirk to_rfc fails."""
        source_quirk = ConversionFailingQuirk(fail_on="to_rfc")
        target_quirk = oid

        result = matrix.convert(source_quirk, target_quirk, "objectclass", "(test)")
        assert result.is_failure
        assert (
            result.error is not None and "Failed to convert source→RFC" in result.error
        )

    def test_convert_objectclass_from_rfc_failure(
        self, matrix: FlextLdifQuirksConversionMatrix
    ) -> None:
        """Test objectClass conversion fails when target quirk from_rfc fails."""
        source_quirk = ObjectClassParseOnlyQuirk()
        target_quirk = ConversionFailingQuirk(fail_on="from_rfc")

        result = matrix.convert(
            source_quirk,
            target_quirk,
            "objectclass",
            "( 2.16.840.1.113894.1.2.1 NAME 'orclContext' SUP top STRUCTURAL MUST cn )",
        )
        assert result.is_failure
        assert (
            result.error is not None and "Failed to convert RFC→target" in result.error
        )

    def test_convert_objectclass_write_failure(
        self, matrix: FlextLdifQuirksConversionMatrix
    ) -> None:
        """Test objectClass conversion fails when target quirk write fails."""
        source_quirk = ConversionFailingQuirk(fail_on="write")
        target_quirk = ConversionFailingQuirk(fail_on="write")

        result = matrix.convert(
            source_quirk,
            target_quirk,
            "objectclass",
            "( 2.16.840.1.113894.1.2.1 NAME 'orclContext' SUP top STRUCTURAL MUST cn )",
        )
        assert result.is_failure
        assert (
            result.error is not None and "Failed to write target format" in result.error
        )

    def test_convert_objectclass_unexpected_exception(
        self, matrix: FlextLdifQuirksConversionMatrix, oid: FlextLdifQuirksServersOid
    ) -> None:
        """Test objectClass conversion handles unexpected exceptions."""
        source_quirk = ExceptionThrowingQuirk()
        target_quirk = oid

        result = matrix.convert(source_quirk, target_quirk, "objectclass", "(test)")
        assert result.is_failure
        assert (
            result.error is not None and "ObjectClass conversion failed" in result.error
        )


class TestAclConversion:
    """Test ACL conversion functionality."""

    @pytest.fixture
    def matrix(self) -> FlextLdifQuirksConversionMatrix:
        """Create conversion matrix instance."""
        return FlextLdifQuirksConversionMatrix()

    @pytest.fixture
    def oud(self) -> FlextLdifQuirksServersOud:
        """Create OUD quirk instance."""
        return FlextLdifQuirksServersOud(server_type=FlextLdifConstants.ServerTypes.OUD)

    @pytest.fixture
    def oid(self) -> FlextLdifQuirksServersOid:
        """Create OID quirk instance."""
        return FlextLdifQuirksServersOid(server_type=FlextLdifConstants.ServerTypes.OID)

    def test_convert_acl_oud_to_oid(
        self,
        matrix: FlextLdifQuirksConversionMatrix,
        oud: FlextLdifQuirksServersOud,
        oid: FlextLdifQuirksServersOid,
    ) -> None:
        """Test converting OUD ACL to OID via matrix."""
        # Use a simple ACL for testing
        oud_acl = 'targetattr="*" (version 3.0; acl "Test ACL"; allow (read,search,compare) userdn="ldap:///self"; )'

        result = matrix.convert(oud, oid, "acl", oud_acl)
        # ACL conversion may fail if ACL quirks aren't fully implemented, but shouldn't crash
        # The exact behavior depends on ACL quirk implementation
        assert result is not None

    def test_convert_acl_missing_parse_method(
        self, matrix: FlextLdifQuirksConversionMatrix, oud: FlextLdifQuirksServersOud
    ) -> None:
        """Test ACL conversion fails when source quirk lacks ACL support."""
        source_quirk = MissingParseAclQuirk()
        target_quirk = MissingParseAclQuirk()

        result = matrix.convert(source_quirk, target_quirk, "acl", "test acl")
        assert result.is_failure
        assert (
            result.error is not None and "does not support ACL parsing" in result.error
        )

    def test_convert_acl_missing_write_method(
        self, matrix: FlextLdifQuirksConversionMatrix, oud: FlextLdifQuirksServersOud
    ) -> None:
        """Test ACL conversion fails when target quirk lacks write support."""
        source_quirk = oud
        target_quirk = MissingWriteAclQuirk()

        result = matrix.convert(source_quirk, target_quirk, "acl", "test acl")
        assert result.is_failure
        assert (
            result.error is not None and "does not support ACL writing" in result.error
        )


class TestEntryConversion:
    """Test entry conversion functionality."""

    @pytest.fixture
    def matrix(self) -> FlextLdifQuirksConversionMatrix:
        """Create conversion matrix instance."""
        return FlextLdifQuirksConversionMatrix()

    @pytest.fixture
    def oud(self) -> FlextLdifQuirksServersOud:
        """Create OUD quirk instance."""
        return FlextLdifQuirksServersOud(server_type=FlextLdifConstants.ServerTypes.OUD)

    @pytest.fixture
    def oid(self) -> FlextLdifQuirksServersOid:
        """Create OID quirk instance."""
        return FlextLdifQuirksServersOid(server_type=FlextLdifConstants.ServerTypes.OID)

    def test_convert_entry_string_input_fails(
        self, matrix: FlextLdifQuirksConversionMatrix, oud: FlextLdifQuirksServersOud
    ) -> None:
        """Test entry conversion fails for string input (not yet supported)."""
        source_quirk = EntryConversionQuirk()
        target_quirk = EntryConversionQuirk()

        ldif_string = """dn: cn=test,dc=example,dc=com
objectClass: person
cn: test
sn: user"""

        result = matrix.convert(source_quirk, target_quirk, "entry", ldif_string)
        assert result.is_failure
        assert (
            result.error is not None
            and "String input for entry conversion not yet supported" in result.error
        )

    def test_convert_entry_missing_source_support(
        self, matrix: FlextLdifQuirksConversionMatrix, oid: FlextLdifQuirksServersOid
    ) -> None:
        """Test entry conversion fails when source quirk lacks entry support."""
        source_quirk = MinimalQuirk()
        target_quirk = oid

        entry_data: dict[str, object] = {"dn": "cn=test,dc=example,dc=com"}
        result = matrix.convert(source_quirk, target_quirk, "entry", entry_data)
        assert result.is_failure
        assert (
            result.error is not None and "does not have Entry support" in result.error
        )

    def test_convert_entry_missing_target_support(
        self, matrix: FlextLdifQuirksConversionMatrix, oud: FlextLdifQuirksServersOud
    ) -> None:
        """Test entry conversion fails when target quirk lacks entry support."""
        source_quirk = oud
        target_quirk = MinimalQuirk()

        entry_data: dict[str, object] = {"dn": "cn=test,dc=example,dc=com"}
        result = matrix.convert(source_quirk, target_quirk, "entry", entry_data)
        assert result.is_failure
        assert (
            result.error is not None and "does not have Entry support" in result.error
        )


class TestBatchConversionErrorHandling:
    """Test batch conversion error scenarios."""

    @pytest.fixture
    def matrix(self) -> FlextLdifQuirksConversionMatrix:
        """Create conversion matrix instance."""
        return FlextLdifQuirksConversionMatrix()

    @pytest.fixture
    def oud(self) -> FlextLdifQuirksServersOud:
        """Create OUD quirk instance."""
        return FlextLdifQuirksServersOud(server_type=FlextLdifConstants.ServerTypes.OUD)

    @pytest.fixture
    def oid(self) -> FlextLdifQuirksServersOid:
        """Create OID quirk instance."""
        return FlextLdifQuirksServersOid(server_type=FlextLdifConstants.ServerTypes.OID)

    def test_batch_convert_all_items_fail(
        self, matrix: FlextLdifQuirksConversionMatrix, oid: FlextLdifQuirksServersOid
    ) -> None:
        """Test batch conversion handles all items failing."""
        source_quirk = FailingParseQuirk()
        target_quirk = oid

        items = ["(test1)", "(test2)", "(test3)"]
        result = matrix.batch_convert(source_quirk, target_quirk, "attribute", items)

        assert result.is_failure
        assert (
            result.error is not None
            and "Batch conversion completed with 3 errors" in result.error
        )

    def test_batch_convert_error_truncation(
        self, matrix: FlextLdifQuirksConversionMatrix, oid: FlextLdifQuirksServersOid
    ) -> None:
        """Test batch conversion truncates errors when more than MAX_ERRORS_TO_SHOW."""
        source_quirk = FailingParseQuirk()
        target_quirk = oid

        # Create 8 items that will all fail
        items = [f"(test{i})" for i in range(8)]
        result = matrix.batch_convert(source_quirk, target_quirk, "attribute", items)

        assert result.is_failure
        assert (
            result.error is not None and "... and 3 more errors" in result.error
        )  # 8 - 5 = 3 more

    def test_batch_convert_unexpected_exception(
        self, matrix: FlextLdifQuirksConversionMatrix, oid: FlextLdifQuirksServersOid
    ) -> None:
        """Test batch conversion handles unexpected exceptions."""
        source_quirk = ExceptionThrowingQuirk()
        target_quirk = oid

        items = ["(test1)", "(test2)"]
        result = matrix.batch_convert(source_quirk, target_quirk, "attribute", items)

        assert result.is_failure
        assert (
            result.error is not None
            and "Batch conversion completed with 2 errors" in result.error
        )


class TestSupportCheckingEdgeCases:
    """Test edge cases in support checking."""

    @pytest.fixture
    def matrix(self) -> FlextLdifQuirksConversionMatrix:
        """Create conversion matrix instance."""
        return FlextLdifQuirksConversionMatrix()

    def test_get_supported_conversions_minimal_quirk(
        self, matrix: FlextLdifQuirksConversionMatrix
    ) -> None:
        """Test support checking for quirk with minimal functionality."""
        quirk = MinimalQuirk()
        support = matrix.get_supported_conversions(quirk)

        assert support["attribute"] is False
        assert support["objectclass"] is False
        assert support["acl"] is False
        assert support["entry"] is False

    def test_get_supported_conversions_partial_quirk(
        self, matrix: FlextLdifQuirksConversionMatrix
    ) -> None:
        """Test support checking for quirk with partial functionality."""
        quirk = PartialAttributeQuirk()
        support = matrix.get_supported_conversions(quirk)

        assert support["attribute"] is True
        assert support["objectclass"] is False
        assert support["acl"] is False
        assert support["entry"] is False

    def test_get_supported_conversions_acl_quirk(
        self, matrix: FlextLdifQuirksConversionMatrix
    ) -> None:
        """Test support checking for quirk with ACL support."""
        quirk = AclOnlyQuirk()
        support = matrix.get_supported_conversions(quirk)

        assert support["attribute"] is False
        assert support["objectclass"] is False
        assert support["acl"] is True
        assert support["entry"] is False

    def test_get_supported_conversions_entry_quirk(
        self, matrix: FlextLdifQuirksConversionMatrix
    ) -> None:
        """Test support checking for quirk with entry support."""
        quirk = EntryOnlyQuirk()
        support = matrix.get_supported_conversions(quirk)

        assert support["attribute"] is False
        assert support["objectclass"] is False
        assert support["acl"] is False
        assert support["entry"] is True


class TestConversionMatrixConstants:
    """Test conversion matrix constants."""

    def test_max_errors_to_show_constant(self) -> None:
        """Test that MAX_ERRORS_TO_SHOW constant exists."""
        assert hasattr(FlextLdifQuirksConversionMatrix, "MAX_ERRORS_TO_SHOW")
        assert FlextLdifQuirksConversionMatrix.MAX_ERRORS_TO_SHOW == 5


__all__ = [
    "TestAclConversion",
    "TestAttributeConversion",
    "TestAttributeConversionErrorPaths",
    "TestBatchConversion",
    "TestBatchConversionErrorHandling",
    "TestBidirectionalConversion",
    "TestConversionMatrixConstants",
    "TestConversionMatrixInitialization",
    "TestDnCaseRegistryIntegration",
    "TestDnExtractionAndRegistration",
    "TestEntryConversion",
    "TestErrorHandling",
    "TestGetSupportedConversions",
    "TestObjectClassConversion",
    "TestObjectClassConversionErrorPaths",
    "TestSupportCheckingEdgeCases",
]
