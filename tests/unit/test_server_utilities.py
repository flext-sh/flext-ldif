from __future__ import annotations

import pytest
from flext_tests import tm

from tests import m, u


class TestFlextLdifUtilitiesServer:
    def test_extract_server_name_failure_no_suffix(self) -> None:
        result = u.Ldif._extract_server_name("FlextLdifServersUnknown")

        u.Tests.assert_failure(result)

    def test_extract_server_name_failure_empty_name_after_suffix(self) -> None:
        result = u.Ldif._extract_server_name("Schema")

        u.Tests.assert_failure(result)

    def test_extract_server_name_success_schema_suffix(self) -> None:
        result = u.Ldif._extract_server_name("OidSchema")
        value = u.Tests.assert_success(result)

        tm.that(value, eq="Oid")

    def test_get_type_from_independent_class_success(self) -> None:
        class FlextLdifServersOidSchema:
            pass

        result = u.Ldif._get_type_from_independent_class(FlextLdifServersOidSchema)

        tm.that(result, eq="oid")

    def test_get_type_from_independent_class_failure_unknown_server(self) -> None:
        class FlextLdifServersUnknownSchema:
            pass

        result = u.Ldif._get_type_from_independent_class(FlextLdifServersUnknownSchema)

        tm.that(result, none=True)

    def test_get_type_from_nested_class_success_from_parent_constants(self) -> None:
        result = u.Ldif._get_type_from_nested_class(m.Ldif.Tests.OidServerStub.Entry)

        tm.that(result, eq="oid")

    def test_extract_server_type_from_constants_success(self) -> None:
        result = u.Ldif.extract_server_type_from_constants(m.Ldif.Tests.OudServerStub)

        tm.that(result, eq="oud")

    def test_get_parent_server_type_failure_raises_attribute_error(self) -> None:
        class Unknown:
            pass

        with pytest.raises(AttributeError):
            u.Ldif.get_parent_server_type(Unknown)
