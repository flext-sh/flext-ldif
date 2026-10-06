"""LDIF DN attribute transformation utilities.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, overload

from flext_cli import u

from flext_ldif import FlextLdifModels, c, t
from flext_ldif._utilities._dn_normalize import FlextLdifDNNormalization
from flext_ldif._utilities._dn_parse import FlextLdifDNParsing

if TYPE_CHECKING:
    from collections.abc import MutableMapping


class FlextLdifDNTransforming:
    """Transform DN attribute values and LDIF file base DNs."""

    @overload
    @staticmethod
    def transform_dn_attribute(value: str, source_dn: str, target_dn: str) -> str: ...

    @overload
    @staticmethod
    def transform_dn_attribute(
        value: FlextLdifModels.Ldif.DN,
        source_dn: str,
        target_dn: str,
    ) -> str: ...

    @staticmethod
    def transform_dn_attribute(
        value: str | FlextLdifModels.Ldif.DN,
        source_dn: str,
        target_dn: str,
    ) -> str:
        """Transform a single DN attribute value by replacing base DN.

        Returns:
            The resulting ``str``.
        """
        dn_str = FlextLdifDNParsing.get_dn_value(value)
        if not dn_str or not source_dn or (not target_dn):
            return dn_str
        norm_result = FlextLdifDNNormalization.norm(dn_str)
        normalized_dn = norm_result.map_or(dn_str)
        source_escaped = c.Ldif.escape_pattern(source_dn)
        result = u.to_str(
            c.Ldif.compile_pattern(
                f",{source_escaped}$",
                ignorecase=True,
            ).sub(f",{target_dn}", normalized_dn),
        )
        if result == normalized_dn:
            result = u.to_str(
                c.Ldif.compile_pattern(
                    f"^{source_escaped}$",
                    ignorecase=True,
                ).sub(target_dn, normalized_dn),
            )
        return result

    @staticmethod
    def _transform_ldif_content(content: str, source_dn: str, target_dn: str) -> str:
        """Transform all DN references in raw LDIF content string.

        Returns:
            The resulting ``str``.
        """
        return u.to_str(
            c.Ldif.compile_pattern(
                c.Ldif.escape_pattern(source_dn),
                ignorecase=True,
            ).sub(target_dn, content),
        )

    @staticmethod
    def transform_ldif_files_in_directory(
        ldif_dir: str | Path,
        source_basedn: str,
        target_basedn: str,
    ) -> MutableMapping[str, int | t.MutableSequenceOf[str]]:
        """Transform base DN in all LDIF files in a directory.

        Reads each .ldif file, replaces source_basedn with target_basedn
        in all DN lines and DN-valued attribute values, and writes back.

        Returns dict with total_count (files transformed) and transformed_files list.

        Returns:
            The resulting ``MutableMapping[str, int | t.MutableSequenceOf[str]]``.
        """
        directory = Path(str(ldif_dir))
        transformed_files: t.MutableSequenceOf[str] = []
        for ldif_file in sorted(directory.glob("*.ldif")):
            content = ldif_file.read_text(encoding=c.Ldif.DEFAULT_ENCODING)
            new_content = FlextLdifDNTransforming._transform_ldif_content(
                content,
                source_basedn,
                target_basedn,
            )
            if new_content != content:
                _ = ldif_file.write_text(new_content, encoding=c.Ldif.DEFAULT_ENCODING)
                transformed_files.append(ldif_file.name)
        return {
            "total_count": len(transformed_files),
            "transformed_files": transformed_files,
        }


__all__: list[str] = ["FlextLdifDNTransforming"]
