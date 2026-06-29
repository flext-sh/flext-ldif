"""Service-layer pipeline orchestration."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated, Self, override

from flext_cli import cli
from flext_ldif import c, m, p, r, s, t, u
from flext_ldif.services.transformers import FlextLdifTransformer


class FlextLdifProcessingPipeline(
    s[t.MutableSequenceOf[m.Ldif.Entry]],
):
    """Full processing pipeline with configuration."""

    _DEFAULT_CASE_FOLD: c.Ldif.CaseFoldOption = c.Ldif.CaseFoldOption.NONE
    _DEFAULT_SPACE_HANDLING: c.Ldif.SpaceHandlingOption = (
        c.Ldif.SpaceHandlingOption.PRESERVE
    )
    transform_config: Annotated[
        m.Ldif.TransformConfig | None,
        u.Field(
            default=None,
            exclude=True,
            description="Optional transformation configuration for the processing pipeline.",
        ),
    ]
    entries_input: Annotated[
        t.MutableSequenceOf[m.Ldif.Entry] | None,
        u.Field(
            default=None,
            exclude=True,
            description="Optional entry batch used when the service executes without explicit input.",
        ),
    ]
    _config: m.Ldif.TransformConfig = u.PrivateAttr(
        default_factory=m.Ldif.TransformConfig,
    )
    _entries: t.MutableSequenceOf[m.Ldif.Entry] = u.PrivateAttr(default_factory=list)
    _stages: t.SequenceOf[m.Cli.PipelineStageSpec] = u.PrivateAttr(
        default_factory=tuple,
    )

    @override
    def model_post_init(self, __context: t.JsonMapping | None, /) -> None:
        """Initialize the processing pipeline after model validation."""
        super().model_post_init(__context)
        self._config = self.transform_config or m.Ldif.TransformConfig()
        self._stages = self._build_pipeline()

    @classmethod
    def for_servers(
        cls,
        *,
        source_server: str | c.Ldif.ServerTypes,
        target_server: str | c.Ldif.ServerTypes,
        base_dn: str = "",
    ) -> Self:
        """Create a configured pipeline for source and target LDIF servers."""
        source_server_type = (
            source_server
            if isinstance(source_server, c.Ldif.ServerTypes)
            else u.Ldif.normalize_server_type(source_server)
        )
        target_server_type = (
            target_server
            if isinstance(target_server, c.Ldif.ServerTypes)
            else u.Ldif.normalize_server_type(target_server)
        )
        cls._get_or_create_logger().debug(
            "Creating processing pipeline",
            source=source_server_type,
            target=target_server_type,
        )
        transform_config = m.Ldif.TransformConfig.servers(
            source_server=source_server_type,
            target_server=target_server_type,
            base_dn=base_dn,
        )
        return cls(transform_config=transform_config)

    @override
    def execute(
        self,
    ) -> p.Result[t.MutableSequenceOf[m.Ldif.Entry]]:
        """Execute the processing pipeline."""
        batch = self.entries_input
        if batch is None:
            return r[t.MutableSequenceOf[m.Ldif.Entry]].fail("No entries provided")
        self._entries = list(batch)
        if not self._stages:
            return r[t.MutableSequenceOf[m.Ldif.Entry]].ok(self._entries)
        pipeline_result = cli.pipeline(
            self._stages,
            workspace_root=Path.cwd(),
            fail_fast=True,
            logger=self.logger,
        )
        if pipeline_result.failure:
            return r[t.MutableSequenceOf[m.Ldif.Entry]].fail(
                pipeline_result.error or "processing pipeline failed"
            )
        failed_stage = next(
            (stage for stage in pipeline_result.value.failed_stages if stage.error),
            None,
        )
        if failed_stage is not None:
            return r[t.MutableSequenceOf[m.Ldif.Entry]].fail(
                failed_stage.error or "processing pipeline failed"
            )
        return r[t.MutableSequenceOf[m.Ldif.Entry]].ok(self._entries)

    def _apply_transformer(
        self,
        stage_id: str,
        transformer: p.Ldif.EntryTransformer,
    ) -> p.Result[m.Cli.PipelineStageResult]:
        """Apply one entry transformer across the current batch."""
        transformed_entries: t.MutableSequenceOf[m.Ldif.Entry] = []
        for entry in self._entries:
            transformed = transformer.apply(entry)
            if transformed.failure:
                return r[m.Cli.PipelineStageResult].fail(
                    transformed.error or f"stage {stage_id} failed"
                )
            transformed_entries.append(transformed.value)
        self._entries = transformed_entries
        output_payload: t.JsonMapping = t.Cli.JSON_MAPPING_ADAPTER.validate_python({
            "processed_entries": len(transformed_entries)
        })
        stage_result: p.Result[m.Cli.PipelineStageResult] = cli.ok_stage(
            stage_id,
            output=output_payload,
        )
        return stage_result

    def _build_pipeline(self) -> t.SequenceOf[m.Cli.PipelineStageSpec]:
        """Build the canonical cli-backed processing stages."""
        stage_order: t.MutableSequenceOf[str] = []
        handlers: t.MutableMappingKV[str, t.Cli.PipelineHandler] = {}
        if self._config.normalize_dns and self._config.process_config is not None:
            dn_config = (
                self._config.process_config.dn_config or m.Ldif.DnNormalizationConfig()
            )
            case_enum = (
                c.Ldif.CaseFoldOption(dn_config.case_fold)
                if dn_config.case_fold is not None
                else self._DEFAULT_CASE_FOLD
            )
            spaces_enum = (
                c.Ldif.SpaceHandlingOption(dn_config.space_handling)
                if dn_config.space_handling is not None
                else self._DEFAULT_SPACE_HANDLING
            )
            normalize_dn = u.Ldif.Normalize.dn(
                case=case_enum,
                spaces=spaces_enum,
                validate=dn_config.validate_before,
            )
            handlers[c.Ldif.PROCESSING_STAGE_NORMALIZE_DN] = (
                lambda _ctx, transformer=normalize_dn: self._apply_transformer(
                    c.Ldif.PROCESSING_STAGE_NORMALIZE_DN,
                    transformer,
                )
            )
            stage_order.append(c.Ldif.PROCESSING_STAGE_NORMALIZE_DN)
        if self._config.normalize_attrs and self._config.process_config is not None:
            attr_config = (
                self._config.process_config.attr_config
                or m.Ldif.AttrNormalizationConfig()
            )
            normalize_attrs = u.Ldif.Normalize.attrs(
                case_fold_names=attr_config.case_fold_names,
                trim_values=attr_config.trim_values,
                remove_empty=attr_config.remove_empty,
            )
            handlers[c.Ldif.PROCESSING_STAGE_NORMALIZE_ATTRS] = (
                lambda _ctx, transformer=normalize_attrs: self._apply_transformer(
                    c.Ldif.PROCESSING_STAGE_NORMALIZE_ATTRS,
                    transformer,
                )
            )
            stage_order.append(c.Ldif.PROCESSING_STAGE_NORMALIZE_ATTRS)
        if (
            self._config.process_config is not None
            and self._config.process_config.source_server
            and self._config.process_config.target_server
        ):
            source_server = c.Ldif.ServerTypes(
                u.Ldif.normalize_server_type(
                    self._config.process_config.source_server,
                ),
            )
            target_server = c.Ldif.ServerTypes(
                u.Ldif.normalize_server_type(
                    self._config.process_config.target_server,
                ),
            )
            server_transform = FlextLdifTransformer(
                source_server=source_server,
                target_server=target_server,
                base_dn=self._config.process_config.base_dn,
            )
            handlers[c.Ldif.PROCESSING_STAGE_SERVER_TRANSFORM] = (
                lambda _ctx, transformer=server_transform: self._apply_transformer(
                    c.Ldif.PROCESSING_STAGE_SERVER_TRANSFORM,
                    transformer,
                )
            )
            stage_order.append(c.Ldif.PROCESSING_STAGE_SERVER_TRANSFORM)
        if c.Ldif.PROCESSING_STAGE_SERVER_TRANSFORM in stage_order:
            stage_order = [
                c.Ldif.PROCESSING_STAGE_SERVER_TRANSFORM,
                *[
                    current_stage_id
                    for current_stage_id in stage_order
                    if current_stage_id != c.Ldif.PROCESSING_STAGE_SERVER_TRANSFORM
                ],
            ]
        return cli.linear_pipeline(stage_order, handlers) if stage_order else ()
