"""LDIF composite facade models and facade-level type aliases.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Annotated, ClassVar

from flext_cli import FlextCliModels
from flext_core import FlextUtilities as u

from flext_ldif import t

if TYPE_CHECKING:
    from flext_ldif.models import FlextLdifModels


class FlextLdifModelsComposite:
    """LDIF composite facade models composed into ``m.Ldif``."""

    class Stats(FlextCliModels.BaseModel):
        """Write statistics for batch content operations."""

        model_config: ClassVar[FlextCliModels.ConfigDict] = FlextCliModels.ConfigDict(
            validate_default=True
        )
        total_entries: Annotated[t.NonNegativeInt, u.Field()] = 0
        successful: Annotated[t.NonNegativeInt, u.Field()] = 0
        failed: Annotated[t.NonNegativeInt, u.Field()] = 0

    class OidAclMetadataConfig(FlextCliModels.BaseModel):
        """Configuration model for OID ACL metadata parsing."""

        acl_line: Annotated[str, u.Field()] = ""
        oid_subject_type: Annotated[str, u.Field()] = ""
        rfc_subject_type: Annotated[str, u.Field()] = ""
        oid_subject_value: Annotated[str, u.Field()] = ""
        perms_dict: Annotated[t.MutableBoolMapping, u.Field()] = u.Field(
            default_factory=dict[str, bool],
        )
        target_dn: Annotated[str, u.Field()] = "entry"
        target_attrs: t.MutableSequenceOf[str] = u.Field(default_factory=list[str])
        acl_filter: Annotated[str, u.Field()] = ""
        acl_constraint: Annotated[str, u.Field()] = ""
        bindmode: Annotated[str, u.Field()] = ""
        deny_group_override: Annotated[bool, u.Field()] = False
        append_to_all: Annotated[bool, u.Field()] = False
        bind_ip_filter: Annotated[str, u.Field()] = ""
        constrain_to_added_object: Annotated[str, u.Field()] = ""

    # Facade-level composite alias: ``FlextLdifModels.Entry`` resolves to the
    # composed LDIF namespace entry model, keeping the api-freeze contract
    # (``flext_ldif.m.Entry`` and ``flext_ldif.FlextLdifModels.Entry`` agree).
    type Entry = FlextLdifModels.Ldif.Entry


__all__: list[str] = ["FlextLdifModelsComposite"]
