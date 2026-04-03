# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
"""Support package."""

from __future__ import annotations

import typing as _t

from flext_core.lazy import install_lazy_exports

if _t.TYPE_CHECKING:
    import tests.support.conftest_factory as _tests_support_conftest_factory

    conftest_factory = _tests_support_conftest_factory
    import tests.support.ldif_data as _tests_support_ldif_data
    from tests.support.conftest_factory import FlextLdifTestConftest, tk

    ldif_data = _tests_support_ldif_data
    import tests.support.real_services as _tests_support_real_services
    from tests.support.ldif_data import LdifSample, LdifTestData

    real_services = _tests_support_real_services
    import tests.support.test_files as _tests_support_test_files
    from tests.support.real_services import FlextLdifTestServiceFactory

    test_files = _tests_support_test_files
    import tests.support.validators as _tests_support_validators
    from tests.support.test_files import FileManager

    validators = _tests_support_validators
    from flext_core.constants import FlextConstants as c
    from flext_core.decorators import FlextDecorators as d
    from flext_core.exceptions import FlextExceptions as e
    from flext_core.handlers import FlextHandlers as h
    from flext_core.mixins import FlextMixins as x
    from flext_core.models import FlextModels as m
    from flext_core.protocols import FlextProtocols as p
    from flext_core.result import FlextResult as r
    from flext_core.service import FlextService as s
    from flext_core.typings import FlextTypes as t
    from flext_core.utilities import FlextUtilities as u
    from tests.support.validators import (
        MockFlextUtilitiesResultHelpers,
        MockMatchers,
        TestValidators,
    )
_LAZY_IMPORTS = {
    "FileManager": "tests.support.test_files",
    "FlextLdifTestConftest": "tests.support.conftest_factory",
    "FlextLdifTestServiceFactory": "tests.support.real_services",
    "LdifSample": "tests.support.ldif_data",
    "LdifTestData": "tests.support.ldif_data",
    "MockFlextUtilitiesResultHelpers": "tests.support.validators",
    "MockMatchers": "tests.support.validators",
    "TestValidators": "tests.support.validators",
    "c": ("flext_core.constants", "FlextConstants"),
    "conftest_factory": "tests.support.conftest_factory",
    "d": ("flext_core.decorators", "FlextDecorators"),
    "e": ("flext_core.exceptions", "FlextExceptions"),
    "h": ("flext_core.handlers", "FlextHandlers"),
    "ldif_data": "tests.support.ldif_data",
    "m": ("flext_core.models", "FlextModels"),
    "p": ("flext_core.protocols", "FlextProtocols"),
    "r": ("flext_core.result", "FlextResult"),
    "real_services": "tests.support.real_services",
    "s": ("flext_core.service", "FlextService"),
    "t": ("flext_core.typings", "FlextTypes"),
    "test_files": "tests.support.test_files",
    "tk": "tests.support.conftest_factory",
    "u": ("flext_core.utilities", "FlextUtilities"),
    "validators": "tests.support.validators",
    "x": ("flext_core.mixins", "FlextMixins"),
}

__all__ = [
    "FileManager",
    "FlextLdifTestConftest",
    "FlextLdifTestServiceFactory",
    "LdifSample",
    "LdifTestData",
    "MockFlextUtilitiesResultHelpers",
    "MockMatchers",
    "TestValidators",
    "c",
    "conftest_factory",
    "d",
    "e",
    "h",
    "ldif_data",
    "m",
    "p",
    "r",
    "real_services",
    "s",
    "t",
    "test_files",
    "tk",
    "u",
    "validators",
    "x",
]


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS)
