from __future__ import annotations

import pytest
from flext_tests import tm

from tests import m, u


class TestsFlextLdifServerUtilities:
    def test_extract_server_type_from_constants_success(self) -> None:
        result = u.Ldif.extract_server_type_from_constants(m.Ldif.Tests.OudServerStub)

        tm.that(result, eq="oud")

    def test_get_parent_server_type_failure_raises_attribute_error(self) -> None:
        class Unknown:
            pass

        with pytest.raises(AttributeError):
            u.Ldif.get_parent_server_type(Unknown)
