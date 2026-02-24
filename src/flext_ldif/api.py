"""FLEXT-LDIF API - Unified Facade for LDIF Operations."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import ClassVar

from flext_core import FlextLogger, r
from pydantic import BaseModel, computed_field

from flext_ldif._utilities.entry import FlextLdifUtilitiesEntry
from flext_ldif.base import FlextLdifServiceBase
from flext_ldif.constants import c
from flext_ldif.models import m
from flext_ldif.protocols import p
from flext_ldif.services.acl import FlextLdifAcl
from flext_ldif.services.analysis import FlextLdifAnalysis
from flext_ldif.services.categorization import FlextLdifCategorization
from flext_ldif.services.detector import FlextLdifDetector
from flext_ldif.services.entries import FlextLdifEntries
from flext_ldif.services.migration import FlextLdifMigrationPipeline
from flext_ldif.services.parser import FlextLdifParser
from flext_ldif.services.processing import FlextLdifProcessing
from flext_ldif.services.server import FlextLdifServer
from flext_ldif.services.statistics import FlextLdifStatistics
from flext_ldif.services.validation import FlextLdifValidation
from flext_ldif.services.writer import FlextLdifWriter
from flext_ldif.settings import FlextLdifSettings
from flext_ldif.typings import t


class FlextLdif(FlextLdifServiceBase[m.Ldif.Entry]):
    """Main API facade for LDIF operations using composition pattern."""

    _instance: ClassVar[FlextLdif | None] = None
    _init_config_overrides: ClassVar[Mapping[str, t.Ldif.JsonValue] | None] = None
    _processing_service: FlextLdifProcessing | None
    _acl_service: FlextLdifAcl | None
    _parser_service: FlextLdifParser | None
    _writer_service: FlextLdifWriter | None
    _detector_service: FlextLdifDetector | None
    _entries_service: FlextLdifEntries | None
    _server_service: FlextLdifServer | None

    @classmethod
    def _set_init_config_overrides(
        cls,
        config: FlextLdifSettings,
    ) -> None:
        """Set temporary init config overrides for runtime bootstrap."""
        cls._init_config_overrides = config.model_dump(exclude_none=True)

    @classmethod
    def _clear_init_config_overrides(cls) -> None:
        """Clear temporary init config overrides after initialization."""
        cls._init_config_overrides = None

    @classmethod
    def _runtime_bootstrap_options(cls) -> p.RuntimeBootstrapOptions:
        """Allow per-instance config overrides on initialization."""
        base_options = super()._runtime_bootstrap_options()
        overrides = cls._init_config_overrides
        if not overrides:
            return base_options
        return base_options.model_copy(update={"config_overrides": dict(overrides)})

    @classmethod
    def get_instance(cls) -> FlextLdif:
        """Get singleton instance of FlextLdif."""
        if cls._instance is None:
            cls._instance = cls()
        instance = cls._instance
        if instance is None:
            msg = "FlextLdif singleton instance was not initialized"
            raise RuntimeError(msg)
        return instance

    @classmethod
    def categorization(
        cls,
        *,
        base_dn: str | None = None,
        server_type: str = "rfc",
    ) -> FlextLdifCategorization:
        """Create a categorization service with the global server registry."""
        return FlextLdifCategorization(
            base_dn=base_dn,
            server_type=server_type,
            server_registry=FlextLdifServer.get_global_instance(),
        )

    def __init__(
        self,
        *,
        config: FlextLdifSettings | None = None,
        **kwargs: str | float | bool | None,
    ) -> None:
        """Initialize LDIF facade."""
        del kwargs

        try:
            if config is not None:
                self._set_init_config_overrides(config)
            super().__init__()
        finally:
            self._clear_init_config_overrides()

        self._processing_service = None
        self._acl_service = None
        self._parser_service = None
        self._writer_service = None
        self._detector_service = None
        self._entries_service = None
        self._server_service = None
        FlextLogger(__name__).info("FlextLdif facade initialized")

    @property
    @computed_field
    def service_stats(self) -> Mapping[str, bool]:
        """Pydantic 2 computed field showing service initialization status."""
        return {
            "parser": self._parser_service is not None,
            "writer": self._writer_service is not None,
            "detector": self._detector_service is not None,
            "validator": True,
            "statistics": True,
            "processing": self._processing_service is not None,
            "acl": self._acl_service is not None,
            "entries": self._entries_service is not None,
            "server": self._server_service is not None,
        }

    @property
    def processing_service(self) -> FlextLdifProcessing:
        """Get processing service instance (lazy initialization)."""
        if self._processing_service is None:
            self._processing_service = FlextLdifProcessing()
        service = self._processing_service
        if service is None:
            msg = "Processing service initialization failed"
            raise RuntimeError(msg)
        return service

    @property
    def acl_service(self) -> FlextLdifAcl:
        """Get ACL service instance (lazy initialization)."""
        if self._acl_service is None:
            self._acl_service = FlextLdifAcl(server=self.server)
        service = self._acl_service
        if service is None:
            msg = "ACL service initialization failed"
            raise RuntimeError(msg)
        return service

    @property
    def models(self) -> type[m]:
        """Get FlextLdifModels class."""
        return m

    @property
    def constants(self) -> type:
        """Get constants (use string literals instead)."""
        return c

    @property
    def parser(self) -> FlextLdifParser:
        """Get parser service instance (lazy initialization)."""
        if self._parser_service is None:
            self._parser_service = FlextLdifParser(server=self.server)
        service = self._parser_service
        if service is None:
            msg = "Parser service initialization failed"
            raise RuntimeError(msg)
        return service

    @property
    def writer(self) -> FlextLdifWriter:
        """Get writer service instance (lazy initialization)."""
        if self._writer_service is None:
            self._writer_service = FlextLdifWriter()
        service = self._writer_service
        if service is None:
            msg = "Writer service initialization failed"
            raise RuntimeError(msg)
        return service

    @property
    def detector(self) -> FlextLdifDetector:
        """Get detector service instance (lazy initialization)."""
        if self._detector_service is None:
            self._detector_service = FlextLdifDetector()
        service = self._detector_service
        if service is None:
            msg = "Detector service initialization failed"
            raise RuntimeError(msg)
        return service

    @property
    def entries_service(self) -> FlextLdifEntries:
        """Get entries service instance (lazy initialization)."""
        if self._entries_service is None:
            self._entries_service = FlextLdifEntries()
        service = self._entries_service
        if service is None:
            msg = "Entries service initialization failed"
            raise RuntimeError(msg)
        return service

    @property
    def server(self) -> FlextLdifServer:
        """Get server registry instance (lazy initialization)."""
        if self._server_service is None:
            self._server_service = FlextLdifServer.get_global_instance()
        service = self._server_service
        if service is None:
            msg = "Server service initialization failed"
            raise RuntimeError(msg)
        return service

    def migrate(
        self,
        input_dir: Path | None = None,
        output_dir: Path | None = None,
        source_server: str = "rfc",
        target_server: str = "rfc",
        options: m.Ldif.MigrateOptions | None = None,
        **kwargs: str | float | bool | None,
    ) -> r[m.Ldif.LdifResults.MigrationPipelineResult]:
        """Migrate LDIF data between servers."""
        if (
            options
            and getattr(options, "write_options", None) is not None
            and options.write_options
        ):
            _ = kwargs.setdefault(
                "fold_long_lines", options.write_options.fold_long_lines
            )
            _ = kwargs.setdefault(
                "sort_attributes", options.write_options.sort_attributes
            )

        source_server_typed: str = str(source_server)
        target_server_typed: str = str(target_server)
        output_filename_raw = kwargs.get("output_filename")
        output_filename: str | None
        match output_filename_raw:
            case str() as filename:
                output_filename = filename
            case _:
                output_filename = None
        pipeline = FlextLdifMigrationPipeline(
            input_dir=input_dir,
            output_dir=output_dir,
            source_server_type=source_server_typed,
            target_server_type=target_server_typed,
            output_filename=output_filename,
        )
        return pipeline.execute()

    def process(
        self,
        processor_name: str,
        entries: list[m.Ldif.Entry],
        *,
        parallel: bool = False,
        batch_size: int = 100,
        max_workers: int = 4,
    ) -> r[list[m.Ldif.ProcessingResult]]:
        """Process entries using processing service."""
        return self.processing_service.process(
            processor_name,
            entries,
            parallel=parallel,
            batch_size=batch_size,
            max_workers=max_workers,
        )

    def extract_acls(
        self,
        entry: m.Ldif.Entry | BaseModel | Mapping[str, t.Ldif.JsonValue],
    ) -> r[m.Ldif.Results.AclResponse]:
        """Extract ACLs from entry."""
        server_type: str = "rfc"

        match entry:
            case m.Ldif.Entry() as ldif_entry:
                entry_typed = ldif_entry
            case BaseModel() as model:
                entry_typed = m.Ldif.Entry.model_validate_json(model.model_dump_json())
            case _:
                entry_typed = m.Ldif.Entry.model_validate(entry)
        return self.acl_service.extract_acls_from_entry(
            entry_typed,
            server_type,
        )

    def get_entry_dn(
        self,
        entry: m.Ldif.Entry | Mapping[str, str | list[str]],
    ) -> r[str]:
        """Get entry DN string."""
        return FlextLdifEntries.get_entry_dn(entry)

    def get_entry_attributes(
        self,
        entry: m.Ldif.Entry | BaseModel | Mapping[str, t.Ldif.JsonValue],
    ) -> r[Mapping[str, list[str]]]:
        """Get entry attributes dictionary."""
        match entry:
            case m.Ldif.Entry() as ldif_entry:
                entry_typed = ldif_entry
            case BaseModel() as model:
                entry_typed = m.Ldif.Entry.model_validate_json(model.model_dump_json())
            case _:
                entry_typed = m.Ldif.Entry.model_validate(entry)
        return FlextLdifEntries.get_entry_attributes(entry_typed)

    def get_entry_objectclasses(
        self,
        entry: m.Ldif.Entry | BaseModel | Mapping[str, t.Ldif.JsonValue],
    ) -> r[list[str]]:
        """Get entry objectClass values."""
        match entry:
            case m.Ldif.Entry() as ldif_entry:
                entry_typed = ldif_entry
            case BaseModel() as model:
                entry_typed = m.Ldif.Entry.model_validate_json(model.model_dump_json())
            case _:
                entry_typed = m.Ldif.Entry.model_validate(entry)
        return FlextLdifEntries.get_entry_objectclasses(entry_typed)

    def get_attribute_values(
        self,
        attribute: str | list[str],
    ) -> r[list[str]]:
        """Get values from attribute value container."""
        return FlextLdifEntries.get_attribute_values(attribute)

    def parse(
        self,
        source: str | Path,
        *,
        server_type: str | None = None,
    ) -> r[list[m.Ldif.Entry]]:
        """Parse LDIF content from string or file."""
        effective_type = server_type or self._get_effective_server_type_value()

        match source:
            case Path() as source_path:
                return self._parse_file(source_path, server_type=effective_type)
            case str() as content:
                source_content = content

        parse_result = self.parser.parse_string(
            source_content,
            server_type=effective_type,
        )
        if parse_result.is_failure:
            return r[list[m.Ldif.Entry]].fail(str(parse_result.error))

        response = parse_result.value
        entries_list: list[m.Ldif.Entry] = [
            m.Ldif.Entry.model_validate_json(entry.model_dump_json())
            for entry in response.entries
        ]
        return r[list[m.Ldif.Entry]].ok(entries_list)

    def _parse_file(
        self,
        path: Path,
        *,
        server_type: str | None = None,
    ) -> r[list[m.Ldif.Entry]]:
        """Parse LDIF file (internal helper)."""
        if not path.exists():
            return r[list[m.Ldif.Entry]].fail(f"File not found: {path}")

        try:
            content = path.read_text(encoding="utf-8")
        except OSError as e:
            return r[list[m.Ldif.Entry]].fail(f"Failed to read file: {e}")

        return self.parse(source=content, server_type=server_type)

    def create_entry(
        self,
        dn: str,
        attributes: Mapping[str, str | list[str]],
        objectclasses: list[str] | None = None,
    ) -> r[m.Ldif.Entry]:
        """Create a new Entry model."""
        return FlextLdifEntries.create_entry(
            dn=dn,
            attributes=attributes,
            objectclasses=objectclasses,
        )

    def detect_server_type(
        self,
        ldif_content: str | Path,
    ) -> r[m.Ldif.LdifResults.ServerDetectionResult]:
        """Detect LDAP server type from LDIF content."""
        content_str: str | None = None
        match ldif_content:
            case Path() as source_path:
                try:
                    content_str = source_path.read_text(encoding="utf-8")
                except OSError as e:
                    return r[m.Ldif.LdifResults.ServerDetectionResult].fail(
                        f"Failed to read file: {e}"
                    )
            case str() as content:
                content_str = content
        return self.detector.detect_server_type(ldif_content=content_str)

    def get_effective_server_type(
        self,
        ldif_content: str | None = None,
    ) -> r[str]:
        """Get effective server type based on config and detection."""
        return self.detector.get_effective_server_type(ldif_content=ldif_content)

    def _get_effective_server_type_value(self) -> str:
        """Get effective server type value (internal helper)."""
        result = self.get_effective_server_type()
        if result.is_success:
            return result.value
        return "rfc"

    def write(
        self,
        entries: list[m.Ldif.Entry],
        *,
        server_type: str | None = None,
        format_options: (
            m.Ldif.LdifResults.WriteFormatOptions
            | m.Ldif.LdifResults.WriteOptions
            | None
        ) = None,
    ) -> r[str]:
        """Write entries to LDIF format string."""
        effective_type = server_type or self._get_effective_server_type_value()
        server_type_typed: str = str(effective_type)
        return self.writer.write_to_string(
            entries,
            server_type=server_type_typed,
            format_options=format_options,
        )

    def write_file(
        self,
        entries: list[m.Ldif.Entry],
        path: Path,
        *,
        server_type: str | None = None,
        format_options: (
            m.Ldif.LdifResults.WriteFormatOptions
            | m.Ldif.LdifResults.WriteOptions
            | None
        ) = None,
    ) -> r[bool]:
        """Write entries to LDIF file."""
        write_result = self.write(
            entries,
            server_type=server_type,
            format_options=format_options,
        )
        if write_result.is_failure:
            return r[bool].fail(str(write_result.error))

        content = write_result.value
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            _ = path.write_text(content, encoding="utf-8")
            return r[bool].ok(value=True)
        except OSError as e:
            return r[bool].fail(f"Failed to write file: {e}")

    def validate_entries(
        self,
        entries: list[m.Ldif.Entry],
    ) -> r[m.Ldif.Results.ValidationResult]:
        """Validate list of entries."""
        validation_service = FlextLdifValidation()
        return FlextLdifAnalysis.validate_entries(
            entries,
            validation_service,
        )

    def filter_entries(
        self,
        entries: list[m.Ldif.Entry],
        filter_func: p.Ldif.PredicateProtocol[m.Ldif.Entry],
    ) -> r[list[m.Ldif.Entry]]:
        """Filter entries using predicate function."""
        try:
            filtered = [entry for entry in entries if filter_func(entry)]
            return r[list[m.Ldif.Entry]].ok(filtered)
        except Exception as e:
            return r[list[m.Ldif.Entry]].fail(f"Filter error: {e}")

    def filter(
        self,
        entries: list[m.Ldif.Entry],
        *,
        objectclass: str | None = None,
        dn_pattern: str | None = None,
        attributes: Mapping[str, str | list[str]] | None = None,
    ) -> r[list[m.Ldif.Entry]]:
        """Filter entries by objectClass, DN pattern and attribute criteria."""
        if not objectclass and not dn_pattern and not attributes:
            return r[list[m.Ldif.Entry]].ok(list(entries))

        required_attrs: list[str] = list(attributes.keys()) if attributes else []
        filtered: list[m.Ldif.Entry] = []
        for entry in entries:
            if not FlextLdifUtilitiesEntry.matches_criteria(
                entry,
                objectclasses=[objectclass] if objectclass else [],
                objectclass_mode="any",
                dn_pattern=dn_pattern,
                required_attrs=required_attrs,
            ):
                continue

            if attributes and entry.attributes is not None:
                attr_map = entry.attributes.attributes
                matches_values = True
                for attr_name, expected in attributes.items():
                    entry_values = attr_map.get(attr_name)
                    if expected is None:
                        continue
                    if entry_values is None:
                        matches_values = False
                        break
                    match expected:
                        case list() as expected_list:
                            expected_values = [str(v) for v in expected_list]
                        case _:
                            expected_values = [str(expected)]
                    existing_values = [str(v) for v in entry_values]
                    if not any(value in existing_values for value in expected_values):
                        matches_values = False
                        break
                if not matches_values:
                    continue

            filtered.append(entry)

        return r[list[m.Ldif.Entry]].ok(filtered)

    def get_entry_statistics(
        self,
        _entries: list[m.Ldif.Entry],
    ) -> r[m.Ldif.Results.EntriesStatistics]:
        """Get statistics for list of entries."""
        stats_service = FlextLdifStatistics()
        return stats_service.calculate_for_entries(_entries)

    def filter_persons(
        self,
        entries: list[m.Ldif.Entry],
    ) -> r[list[m.Ldif.Entry]]:
        """Filter entries to only person entries."""
        person_classes = {"person", "inetorgperson", "organizationalperson"}

        class IsPersonPredicate:
            """Predicate class matching Protocol[T].__call__ signature."""

            def __call__(self, item: m.Ldif.Entry) -> bool:
                """Check if entry belongs to a person class."""
                attrs = item.attributes
                if attrs is None:
                    return False
                objectclasses = attrs.attributes.get("objectClass", [])

                match objectclasses:
                    case str() as value:
                        objectclasses_list: list[str] = [value]
                    case list() as values:
                        objectclasses_list = [str(oc) for oc in values]
                    case _:
                        return False

                return any(oc.lower() in person_classes for oc in objectclasses_list)

        return self.filter_entries(entries, IsPersonPredicate())

    def execute(self) -> r[m.Ldif.Entry]:
        """Execute service health check for FlextService pattern compliance."""
        try:
            _ = self.parser
            _ = self.writer
            _ = self.detector

            health_entry = m.Ldif.Entry.model_validate({
                "dn": "cn=health-check",
                "attributes": {"cn": ["health-check"]},
            })
            return r[m.Ldif.Entry].ok(health_entry)
        except Exception as e:
            return r[m.Ldif.Entry].fail(f"Health check failed: {e}")


__all__ = ["FlextLdif"]
