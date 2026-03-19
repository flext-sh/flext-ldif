from __future__ import annotations

from typing import Final

from flext_core import FlextLogger

from flext_ldif.constants import FlextLdifConstants as c
from flext_ldif.models import FlextLdifModels as m
from flext_ldif.services.pipeline import ProcessingPipeline

logger: Final = FlextLogger(__name__)


class FlextLdifProcessingPipelineService:
    __slots__ = ("_processing_pipeline",)

    def __init__(self) -> None:
        self._processing_pipeline: ProcessingPipeline | None = None

    def get_processing_pipeline(
        self,
        source_server_type: c.Ldif.ServerTypes,
        target_server_type: c.Ldif.ServerTypes,
    ) -> ProcessingPipeline:
        pipeline = self._processing_pipeline
        if pipeline is None:
            source_type = m.Ldif.ServerType(source_server_type)
            target_type = m.Ldif.ServerType(target_server_type)
            logger.debug(
                "Creating processing pipeline",
                source=source_type,
                target=target_type,
            )
            process_config = m.Ldif.ProcessConfig(
                batch_size=100,
                timeout_seconds=300,
                max_retries=3,
                source_server=source_type,
                target_server=target_type,
                dn_config=None,
                attr_config=None,
                acl_config=None,
                validation_config=None,
                metadata_config=None,
            )
            config = m.Ldif.TransformConfig(
                fail_fast=False,
                preserve_order=True,
                track_changes=False,
                normalize_dns=False,
                normalize_attrs=False,
                process_config=process_config,
            )
            pipeline = ProcessingPipeline(config)
            self._processing_pipeline = pipeline
        return pipeline


__all__ = ["FlextLdifProcessingPipelineService"]
