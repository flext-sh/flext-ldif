from __future__ import annotations

import pytest
from flext_tests import u
from tests import s

from flext_ldif._utilities.server import FlextLdifUtilitiesServer


class OidServer:
    """Stub OID server for testing."""

    class Constants:
        """OID server constants."""

        SERVER_TYPE = "oid"

    class Entry:
        """OID entry stub."""


class OudServer:
    """Stub OUD server for testing."""

    class Constants:
        """OUD server constants."""

        SERVER_TYPE = "oud"


class TestFlextLdifUtilitiesServer(s):
    def test_extract_server_name_failure_no_suffix(self) -> None:
        result = FlextLdifUtilitiesServer._extract_server_name(
            "FlextLdifServersUnknown"
        )

        self.assert_failure(result)

    def test_extract_server_name_failure_empty_name_after_suffix(self) -> None:
        result = FlextLdifUtilitiesServer._extract_server_name("Schema")

        self.assert_failure(result)

    def test_extract_server_name_success_schema_suffix(self) -> None:
        result = FlextLdifUtilitiesServer._extract_server_name("OidSchema")
        value = self.assert_success(result)

        u.Tests.Matchers.that(value == "Oid", eq=True)

    def test_get_type_from_independent_class_success(self) -> None:
        class FlextLdifServersOidSchema:
            pass

        result = FlextLdifUtilitiesServer._get_type_from_independent_class(
            FlextLdifServersOidSchema
        )

        u.Tests.Matchers.that(result == "oid", eq=True)

    def test_get_type_from_independent_class_failure_unknown_server(self) -> None:
        class FlextLdifServersUnknownSchema:
            pass

        result = FlextLdifUtilitiesServer._get_type_from_independent_class(
            FlextLdifServersUnknownSchema
        )

        u.Tests.Matchers.that(result is None, eq=True)

    def test_get_type_from_nested_class_success_from_parent_constants(self) -> None:
        result = FlextLdifUtilitiesServer._get_type_from_nested_class(OidServer.Entry)

        u.Tests.Matchers.that(result == "oid", eq=True)

    def test_extract_server_type_from_constants_success(self) -> None:
        result = FlextLdifUtilitiesServer.extract_server_type_from_constants(OudServer)

        u.Tests.Matchers.that(result == "oud", eq=True)

    def test_get_parent_server_type_failure_raises_attribute_error(self) -> None:
        class Unknown:
            pass

        with pytest.raises(AttributeError):
            FlextLdifUtilitiesServer.get_parent_server_type(Unknown)
