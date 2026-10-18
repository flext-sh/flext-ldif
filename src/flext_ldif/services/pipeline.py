"""Ordered LDIF transformations using the canonical result traversal.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from functools import partial
from typing import Self, override

from flext_ldif import c, m, p, r, s, t, u
from flext_ldif.services import FlextLdifTransformer


class FlextLdifProcessingPipeline(
    s[t.SequenceOf[p.Ldif.Entry]],
    m.Ldif.RegistryPortOptions,
    m.Ldif.ProcessingPipelineOptions,
):
    """Apply DN, attribute and dialect transforms in their declared order."""

    @classmethod
    def for_servers(
        cls,
        *,
        registry: p.Registry,
        runtime_settings: p.Ldif.Settings | None = None,
        source_server: str | c.Ldif.ServerTypes,
        target_server: str | c.Ldif.ServerTypes,
        base_dn: str = "",
    ) -> Self:
        """Construct one configured pipeline with its explicit registry port.

        Returns:
            A configured ``FlextLdifProcessingPipeline`` instance.

        """
        return cls(
            transform_config=m.Ldif.TransformConfig.servers(
                source_server=u.Ldif.normalize_server_type(source_server),
                target_server=u.Ldif.normalize_server_type(target_server),
                base_dn=base_dn,
            ),
            registry=registry,
            runtime_settings=runtime_settings,
        )

    @override
    def execute(self) -> p.Result[t.SequenceOf[p.Ldif.Entry]]:
        """Transform each complete batch before starting the following stage.

        Returns:
            The resulting ``p.Result[t.SequenceOf[p.Ldif.Entry]]``.

        """
        batch = self.entries_input
        if batch is None:
            return r[t.SequenceOf[p.Ldif.Entry]].fail("No entries provided")
        configuration = self.transform_config or m.Ldif.TransformConfig()
        process = configuration.process_config
        if configuration.normalize_dns and process is not None:
            options = process.dn_config or m.Ldif.DnNormalizationConfig()
            result = r.traverse(
                batch,
                partial(
                    u.Ldif.normalize_entry_dn,
                    case=(
                        c.Ldif.CaseFoldOption(options.case_fold)
                        if options.case_fold is not None
                        else c.Ldif.CaseFoldOption.NONE
                    ),
                    spaces=(
                        c.Ldif.SpaceHandlingOption(options.space_handling)
                        if options.space_handling is not None
                        else c.Ldif.SpaceHandlingOption.PRESERVE
                    ),
                    validate=options.validate_before,
                ),
            )
            if result.failure:
                return r[t.SequenceOf[p.Ldif.Entry]].from_failure(result)
            batch = result.value
        if configuration.normalize_attrs and process is not None:
            attr_options = process.attr_config or m.Ldif.AttrNormalizationConfig()
            result = r.traverse(
                batch,
                partial(
                    u.Ldif.normalize_entry_attrs,
                    case_fold_names=attr_options.case_fold_names,
                    trim_values=attr_options.trim_values,
                    remove_empty=attr_options.remove_empty,
                ),
            )
            if result.failure:
                return r[t.SequenceOf[p.Ldif.Entry]].from_failure(result)
            batch = result.value
        if process is not None and process.source_server and process.target_server:
            transformer = FlextLdifTransformer(
                source_server=u.Ldif.normalize_server_type(process.source_server),
                target_server=u.Ldif.normalize_server_type(process.target_server),
                base_dn=process.base_dn,
                registry=self.registry,
                runtime_settings=self.settings,
            )
            result = r.traverse(batch, transformer.apply)
            if result.failure:
                return r[t.SequenceOf[p.Ldif.Entry]].from_failure(result)
            batch = result.value
        return r[t.SequenceOf[p.Ldif.Entry]].ok(list(batch))


__all__: list[str] = ["FlextLdifProcessingPipeline"]
