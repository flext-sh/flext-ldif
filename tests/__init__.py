# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
"""Tests package."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING as _TYPE_CHECKING

from flext_core.lazy import install_lazy_exports, merge_lazy_imports

if _TYPE_CHECKING:
    from flext_core import FlextTypes
    from flext_tests import d, e, h, r, x

    from tests.base import *
    from tests.conftest import *
    from tests.conftest_shared import *
    from tests.constants import *
    from tests.e2e import *
    from tests.helpers import *
    from tests.integration import *
    from tests.models import *
    from tests.protocols import *
    from tests.support import *
    from tests.test_factory import *
    from tests.test_helpers import *
    from tests.typings import *
    from tests.unit import *
    from tests.unit.__init__ import *
    from tests.unit._utilities.oid import *
    from tests.unit._utilities.parser import *
    from tests.unit._utilities.server import *
    from tests.unit.constants import *
    from tests.unit.protocols import *
    from tests.unit.quirks.servers import *
    from tests.unit.services import *
    from tests.unit.utilities import *
    from tests.utilities import *

_LAZY_IMPORTS: Mapping[str, str | Sequence[str]] = merge_lazy_imports(
    (
        "tests.e2e",
        "tests.helpers",
        "tests.integration",
        "tests.support",
        "tests.unit",
    ),
    {
        "FIXTURES_DIR": "tests.conftest",
        "FlextLdifFixtures": "tests.conftest",
        "FlextLdifTestConstants": "tests.constants",
        "FlextLdifTestFactory": "tests.test_factory",
        "FlextLdifTestModels": "tests.models",
        "FlextLdifTestProtocols": "tests.protocols",
        "FlextLdifTestTypes": "tests.typings",
        "FlextLdifTestUtilities": "tests.utilities",
        "FlextLdifTestsServiceBase": "tests.base",
        "GenericFieldsDict": "tests.typings",
        "OID_FIXTURES_DIR": "tests.conftest",
        "TestsFlextLdifMatchers": "tests.test_helpers",
        "TestsFlextLdifTypes": "tests.test_helpers",
        "TestsFlextLdifValidators": "tests.test_helpers",
        "base": "tests.base",
        "c": ("tests.constants", "FlextLdifTestConstants"),
        "conftest": "tests.conftest",
        "conftest_shared": "tests.conftest_shared",
        "constants": "tests.constants",
        "d": "flext_tests",
        "e": "flext_tests",
        "e2e": "tests.e2e",
        "flext_ldif": "tests.conftest",
        "h": "flext_tests",
        "helpers": "tests.helpers",
        "integration": "tests.integration",
        "large_test_dataset": "tests.conftest_shared",
        "ldif_parser": "tests.conftest",
        "ldif_writer": "tests.conftest",
        "m": ("tests.models", "FlextLdifTestModels"),
        "models": "tests.models",
        "p": ("tests.protocols", "FlextLdifTestProtocols"),
        "parametrized_real_data": "tests.conftest_shared",
        "protocols": "tests.protocols",
        "pytest_configure": "tests.conftest",
        "r": "flext_tests",
        "real_entry": "tests.conftest_shared",
        "real_ldif_content": "tests.conftest_shared",
        "real_ldif_group_entry": "tests.conftest",
        "real_ldif_multiple_entries": "tests.conftest",
        "real_ldif_user_entry": "tests.conftest",
        "s": "tests.base",
        "sample_ldif_entries": "tests.conftest",
        "support": "tests.support",
        "t": ("tests.typings", "FlextLdifTestTypes"),
        "temp_file": "tests.conftest",
        "test_factory": "tests.test_factory",
        "test_helpers": "tests.test_helpers",
        "tf": "tests.test_helpers",
        "tm": "tests.test_helpers",
        "tt": "tests.test_helpers",
        "tv": "tests.test_helpers",
        "typings": "tests.typings",
        "u": ("tests.utilities", "FlextLdifTestUtilities"),
        "unit": "tests.unit",
        "utilities": "tests.utilities",
        "x": "flext_tests",
    },
)


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS)
