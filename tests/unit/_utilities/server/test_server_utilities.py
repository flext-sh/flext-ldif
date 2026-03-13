from __future__ import annotations

import pytest
from tests import s

from flext_ldif._utilities.server import FlextLdifUtilitiesServer


class OidServer:
    class Constants:
        SERVER_TYPE = "oid"

    class Entry:
        pass


class OudServer:
    class Constants:
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

        assert value == "Oid"

    def test_get_type_from_independent_class_success(self) -> None:
        class FlextLdifServersOidSchema:
            pass

        result = FlextLdifUtilitiesServer._get_type_from_independent_class(
            FlextLdifServersOidSchema
        )

        assert result == "oid"

    def test_get_type_from_independent_class_failure_unknown_server(self) -> None:
        class FlextLdifServersUnknownSchema:
            pass

        result = FlextLdifUtilitiesServer._get_type_from_independent_class(
            FlextLdifServersUnknownSchema
        )

        assert result is None

    def test_get_type_from_nested_class_success_from_parent_constants(self) -> None:
        result = FlextLdifUtilitiesServer._get_type_from_nested_class(OidServer.Entry)

        assert result == "oid"

    def test_extract_server_type_from_constants_success(self) -> None:
        result = FlextLdifUtilitiesServer.extract_server_type_from_constants(OudServer)

        assert result == "oud"

    def test_get_parent_server_type_failure_raises_attribute_error(self) -> None:
        class Unknown:
            pass

        with pytest.raises(AttributeError):
            FlextLdifUtilitiesServer.get_parent_server_type(Unknown)
