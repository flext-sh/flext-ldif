"""LDIF composite facade models and facade-level type aliases.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import (
    Iterable,
    Iterator,
    Mapping,
    MutableMapping,
    MutableSequence,
    Sequence,
)

from collections.abc import MutableSequence
from typing import Annotated, ClassVar

from flext_cli import m

from flext_ldif import t


class FlextLdifModelsComposite:
    """LDIF composite facade models composed into ``m.Ldif``."""

    class Stats(m.BaseModel):
        """Write statistics for batch content operations."""

        model_config: ClassVar[m.ConfigDict] = m.ConfigDict(validate_default=True)
        total_entries: Annotated[t.NonNegativeInt, m.Field()] = 0
        successful: Annotated[t.NonNegativeInt, m.Field()] = 0
        failed: Annotated[t.NonNegativeInt, m.Field()] = 0

    class OidAclMetadataConfig(m.BaseModel):
        """Configuration model for OID ACL metadata parsing."""

        acl_line: Annotated[str, m.Field()] = ""
        oid_subject_type: Annotated[str, m.Field()] = ""
        rfc_subject_type: Annotated[str, m.Field()] = ""
        oid_subject_value: Annotated[str, m.Field()] = ""
        perms_dict: Annotated[t.MutableBoolMapping, m.Field()] = m.Field(
            default_factory=dict[str, bool],
        )
        target_dn: Annotated[str, m.Field()] = "entry"
        target_attrs: MutableSequence[str] = m.Field(default_factory=list[str])
        acl_filter: Annotated[str, m.Field()] = ""
        acl_constraint: Annotated[str, m.Field()] = ""
        bindmode: Annotated[str, m.Field()] = ""
        deny_group_override: Annotated[bool, m.Field()] = False
        append_to_all: Annotated[bool, m.Field()] = False
        bind_ip_filter: Annotated[str, m.Field()] = ""
        constrain_to_added_object: Annotated[str, m.Field()] = ""


__all__: list[str] = ["FlextLdifModelsComposite"]
