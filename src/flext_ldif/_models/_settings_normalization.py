"""LDIF settings mix-in: normalization.

from flext_ldif import m
from flext_ldif import u
Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from typing import Annotated

from flext_core import FlextUtilities as u, m


class FlextLdifModelsSettingsNormalization:
    """LDIF settings mix-in: normalization."""

    class DnNormalizationConfig(m.Value):
        """Configuration for DN normalization."""

        case_sensitive: Annotated[
            bool,
            u.Field(description="Whether DN comparison is case-sensitive"),
        ] = False
        remove_spaces: Annotated[
            bool,
            u.Field(description="Remove spaces around DN component separators"),
        ] = True
        case_fold: Annotated[
            str | None,
            u.Field(description="Case folding strategy for DN comparison"),
        ] = None
        space_handling: Annotated[
            str | None,
            u.Field(description="Strategy for handling spaces in DN values"),
        ] = None
        escape_handling: Annotated[
            str | None,
            u.Field(description="Strategy for handling escape sequences in DN"),
        ] = None
        validate_before: Annotated[
            bool,
            u.Field(description="Validate DN format before normalization"),
        ] = True

    class AttrNormalizationConfig(m.Value):
        """Configuration for attribute normalization."""

        lowercase_keys: Annotated[
            bool,
            u.Field(description="Convert attribute names to lowercase"),
        ] = True
        sort_values: Annotated[
            bool,
            u.Field(description="Sort attribute values alphabetically"),
        ] = True
        sort_attributes: Annotated[
            str | None,
            u.Field(description="Attribute sorting strategy"),
        ] = None
        normalize_whitespace: Annotated[
            bool,
            u.Field(description="Normalize whitespace in attribute values"),
        ] = True
        case_fold_names: Annotated[
            bool,
            u.Field(description="Case-fold attribute names for comparison"),
        ] = True
        trim_values: Annotated[
            bool,
            u.Field(description="Trim leading and trailing whitespace from values"),
        ] = True
        remove_empty: Annotated[
            bool,
            u.Field(description="Remove attributes with empty values"),
        ] = False
