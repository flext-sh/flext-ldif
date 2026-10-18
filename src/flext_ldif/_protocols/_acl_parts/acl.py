"""ACL protocol - ACL model contract.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from flext_ldif import t


@runtime_checkable
class AclProtocol(Protocol):
    """ACL model contract."""

    @property
    def name(self) -> str:
        """ACL name."""
        ...

    @property
    def targetattr(self) -> str:
        """Target attribute clause."""
        ...

    @property
    def targetfilter(self) -> str | None:
        """Target filter clause."""
        ...

    @property
    def targetscope(self) -> str | None:
        """Target scope clause."""
        ...

    @property
    def acl_name(self) -> str:
        """ACL rule name."""
        ...

    @property
    def allows(self) -> t.SequenceOf[AclAllowProtocol]:
        """Allow clauses."""
        ...

    @property
    def notes(self) -> t.StrSequence:
        """Notes."""
        ...


@runtime_checkable
class AclAllowProtocol(Protocol):
    """Rendered allow-clause contract."""

    @property
    def subject_type(self) -> str: ...

    @property
    def subject_value(self) -> str: ...

    @property
    def permissions(self) -> t.StrSequence: ...

    @property
    def authmethod(self) -> str: ...

    @property
    def ip(self) -> str: ...


__all__: tuple[str, ...] = ("AclAllowProtocol", "AclProtocol")
