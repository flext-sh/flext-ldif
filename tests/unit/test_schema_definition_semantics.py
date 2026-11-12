"""Native RFC schema equivalence used by authoritative LDAP convergence.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

import pytest

from flext_ldif import u


@pytest.mark.parametrize(
    ("attribute", "before", "after", "equal"),
    [
        (
            "objectclasses",
            "( 1.2.3 NAME 'a' STRUCTURAL MAY x )",
            "(1.2.3 NAME 'a' STRUCTURAL MAY x X-SCHEMA-FILE '99-user.ldif')",
            True,
        ),
        (
            "objectclasses",
            "( 1.2.3 NAME 'a' STRUCTURAL MAY x )",
            "( 1.2.3 NAME 'a' SUP parent STRUCTURAL MAY x )",
            False,
        ),
        (
            "objectclasses",
            "( 1.2.3 NAME 'a' STRUCTURAL MAY x )",
            "( 1.2.3 NAME 'a' AUXILIARY MAY x )",
            False,
        ),
        (
            "objectclasses",
            "( 1.2.3 NAME 'a' STRUCTURAL MUST x )",
            "( 1.2.3 NAME 'a' STRUCTURAL MAY x )",
            False,
        ),
        (
            "objectclasses",
            "( 1.2.3 NAME ( 'a' 'b' ) STRUCTURAL MAY ( x $ y ) )",
            "( 1.2.3 NAME ( 'b' 'a' ) STRUCTURAL MAY ( y $ x ) )",
            True,
        ),
        (
            "attributetypes",
            "( 1.2.3 NAME 'a' SYNTAX 1.2.4 )",
            "( 1.2.3 NAME 'a' SYNTAX 1.2.5 )",
            False,
        ),
        (
            "attributetypes",
            "( 1.2.3 NAME 'a' SYNTAX 1.2.4 )",
            "( 1.2.3 NAME 'a' COLLECTIVE SYNTAX 1.2.4 )",
            False,
        ),
        (
            "attributetypes",
            "( 1.2.3 NAME 'a' SYNTAX 1.2.4 )",
            "( 1.2.3 NAME 'a' OBSOLETE SYNTAX 1.2.4 )",
            False,
        ),
    ],
)
def test_schema_definition_semantics(
    attribute: str, before: str, after: str, *, equal: bool
) -> None:
    """Assert schema definition semantics equality matches ``equal``.

    Raises:
        AssertionError: If the equality result differs from ``equal``.

    """
    matches = u.Ldif.schema_definition_semantics(
        attribute, before
    ) == u.Ldif.schema_definition_semantics(attribute, after)
    if matches is not equal:
        raise AssertionError
