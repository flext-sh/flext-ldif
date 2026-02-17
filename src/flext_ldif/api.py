"""FLEXT-LDIF API - Unified Facade for LDIF Operations."""

from __future__ import annotations

from pathlib import Path
from typing import ClassVar

from flext_core import FlextLogger, r
from pydantic import BaseModel, computed_field

from flext_ldif.base import FlextLdifServiceBase
from flext_ldif.constants import c
from flext_ldif.models import m
from flext_ldif.protocols import p
from flext_ldif.services.acl import FlextLdifAcl
from flext_ldif.services.analysis import FlextLdifAnalysis
from flext_ldif.services.detector import FlextLdifDetector
from flext_ldif.services.entries import FlextLdifEntries
from flext_ldif.services.migration import FlextLdifMigrationPipeline
from flext_ldif.services.parser import FlextLdifParser
from flext_ldif.services.processing import FlextLdifProcessing
from flext_ldif.services.server import FlextLdifServer
from flext_ldif.services.statistics import FlextLdifStatistics
from flext_ldif.services.validation import FlextLdifValidation
from flext_ldif.services.writer import FlextLdifWriter
from flext_ldif.typings import t


class FlextLdif(FlextLdifServiceBase[object]):
    """Main API facade for LDIF operations using composition pattern."""

    _instance: ClassVar[FlextLdif | None] = None
    _service_cache: dict[str, t.GeneralValueType]

    @classmethod
    def get_instance(cls) -> FlextLdif:
        """Get singleton instance of FlextLdif."""
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def __init__(self, **kwargs: str | float | bool | None) -> None:
        """Initialize LDIF facade."""
        super().__init__(**kwargs)

        self._service_cache = {}
        FlextLogger(__name__).info("FlextLdif facade initialized")

    def _get_service_cache(self) -> dict[str, t.GeneralValueType]:
        """Get service cache dict."""
        return self._service_cache

    @property
    @computed_field
    def service_stats(self) -> dict[str, bool]:
        """Pydantic 2 computed field showing service initialization status."""
        cache = self._get_service_cache()
        return {
            "parser": "parser" in cache,
            "writer": "writer" in cache,
            "detector": "detector" in cache,
            "validator": "validator" in cache,
            "statistics": "statistics" in cache,
            "processing": "processing" in cache,
            "acl": "acl" in cache,
            "entries": "entries" in cache,
            "server": "server" in cache,
        }

    @property
    def processing_service(self) -> FlextLdifProcessing:
        """Get processing service instance (lazy initialization)."""
        cache = self._get_service_cache()
        if "processing_service" not in cache:
            cache["processing_service"] = FlextLdifProcessing()
        svc = cache["processing_service"]
        if not isinstance(svc, FlextLdifProcessing):
            svc = FlextLdifProcessing()
            cache["processing_service"] = svc
        return svc

    @property
    def acl_service(self) -> FlextLdifAcl:
        """Get ACL service instance (lazy initialization)."""
        cache = self._get_service_cache()
        if "acl_service" not in cache:
            cache["acl_service"] = FlextLdifAcl(server=self.server)
        svc = cache["acl_service"]
        if not isinstance(svc, FlextLdifAcl):
            svc = FlextLdifAcl(server=self.server)
            cache["acl_service"] = svc
        return svc

    @property
    def models(self) -> type[m]:
        """Get FlextLdifModels class."""
        return m

    @property
    def constants(self) -> object:
        """Get constants (use string literals instead)."""
        return c

    @property
    def parser(self) -> FlextLdifParser:
        """Get parser service instance (lazy initialization)."""
        cache = self._get_service_cache()
        if "parser" not in cache:
            cache["parser"] = FlextLdifParser(server=self.server)
        parser = cache["parser"]
        if not isinstance(parser, FlextLdifParser):
            parser = FlextLdifParser(server=self.server)
            cache["parser"] = parser
        return parser

    @property
    def writer(self) -> FlextLdifWriter:
        """Get writer service instance (lazy initialization)."""
        cache = self._get_service_cache()
        if "writer" not in cache:
            cache["writer"] = FlextLdifWriter()
        writer = cache["writer"]
        if not isinstance(writer, FlextLdifWriter):
            writer = FlextLdifWriter()
            cache["writer"] = writer
        return writer

    @property
    def detector(self) -> FlextLdifDetector:
        """Get detector service instance (lazy initialization)."""
        cache = self._get_service_cache()
        if "detector" not in cache:
            cache["detector"] = FlextLdifDetector()
        detector = cache["detector"]
        if not isinstance(detector, FlextLdifDetector):
            detector = FlextLdifDetector()
            cache["detector"] = detector
        return detector

    @property
    def entries_service(self) -> FlextLdifEntries:
        """Get entries service instance (lazy initialization)."""
        cache = self._get_service_cache()
        if "entries_service" not in cache:
            cache["entries_service"] = FlextLdifEntries()
        entries_svc = cache["entries_service"]
        if not isinstance(entries_svc, FlextLdifEntries):
            entries_svc = FlextLdifEntries()
            cache["entries_service"] = entries_svc
        return entries_svc

    @property
    def server(self) -> FlextLdifServer:
        """Get server registry instance (lazy initialization)."""
        cache = self._get_service_cache()
        if "server" not in cache:
            cache["server"] = FlextLdifServer()
        server = cache["server"]
        if not isinstance(server, FlextLdifServer):
            server = FlextLdifServer()
            cache["server"] = server
        return server

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
        if options and hasattr(options, "write_options") and options.write_options:
            kwargs.setdefault("fold_long_lines", options.write_options.fold_long_lines)
            kwargs.setdefault("sort_attributes", options.write_options.sort_attributes)

        source_server_typed: str = str(source_server)
        target_server_typed: str = str(target_server)
        pipeline = FlextLdifMigrationPipeline(
            input_dir=input_dir,
            output_dir=output_dir,
            source_server_type=source_server_typed,
            target_server_type=target_server_typed,
            **kwargs,
        )
        return pipeline.execute()

    def process(
        self,
        processor_name: str,
        entries: list[t.GeneralValueType],
        *,
        parallel: bool = False,
        batch_size: int = 100,
        max_workers: int = 4,
    ) -> r[list[m.Ldif.ProcessingResult]]:
        """Process entries using processing service."""
        entries_typed: list[m.Ldif.Entry] = []
        for entry in entries:
            match entry:
                case m.Ldif.Entry():
                    entries_typed.append(entry)
                case BaseModel():
                    entry_json = entry.model_dump_json()
                    entries_typed.append(m.Ldif.Entry.model_validate_json(entry_json))
                case _:
                    entries_typed.append(m.Ldif.Entry.model_validate(entry))
        return self.processing_service.process(
            processor_name,
            entries_typed,
            parallel=parallel,
            batch_size=batch_size,
            max_workers=max_workers,
        )

    def extract_acls(
        self,
        entry: object,
    ) -> r[m.Ldif.Results.AclResponse]:
        """Extract ACLs from entry."""
        server_type: str = "rfc"

        if isinstance(entry, m.Ldif.Entry):
            entry_typed = entry
        elif isinstance(entry, BaseModel):
            entry_json = entry.model_dump_json()
            entry_typed = m.Ldif.Entry.model_validate_json(entry_json)
        else:
            entry_typed = m.Ldif.Entry.model_validate(entry)
        return self.acl_service.extract_acls_from_entry(
            entry_typed,
            server_type,
        )

    def get_entry_dn(
        self,
        entry: m.Ldif.Entry | dict[str, str | list[str]] | t.GeneralValueType,
    ) -> r[str]:
        """Get entry DN string."""
        return FlextLdifEntries.get_entry_dn(entry)

    def get_entry_attributes(
        self,
        entry: object,
    ) -> r[dict[str, list[str]]]:
        """Get entry attributes dictionary."""
        if isinstance(entry, m.Ldif.Entry):
            entry_typed = entry
        elif isinstance(entry, BaseModel):
            entry_json = entry.model_dump_json()
            entry_typed = m.Ldif.Entry.model_validate_json(entry_json)
        else:
            entry_typed = m.Ldif.Entry.model_validate(entry)
        return FlextLdifEntries.get_entry_attributes(entry_typed)

    def get_entry_objectclasses(
        self,
        entry: object,
    ) -> r[list[str]]:
        """Get entry objectClass values."""
        if isinstance(entry, m.Ldif.Entry):
            entry_typed = entry
        elif isinstance(entry, BaseModel):
            entry_json = entry.model_dump_json()
            entry_typed = m.Ldif.Entry.model_validate_json(entry_json)
        else:
            entry_typed = m.Ldif.Entry.model_validate(entry)
        return FlextLdifEntries.get_entry_objectclasses(entry_typed)

    def get_attribute_values(
        self,
        attribute: t.GeneralValueType,
    ) -> r[list[str]]:
        """Get values from attribute object."""
        return FlextLdifEntries.get_attribute_values(attribute)

    def parse(
        self,
        content: str | Path,
        *,
        server_type: str | None = None,
    ) -> r[list[t.GeneralValueType]]:
        """Parse LDIF content from string or file."""
        effective_type = server_type or self._get_effective_server_type_value()

        if isinstance(content, Path):
            return self._parse_file(content, server_type=effective_type)

        parse_result = self.parser.parse_string(
            content,
            server_type=effective_type,
        )
        if parse_result.is_failure:
            return r[list[t.GeneralValueType]].fail(str(parse_result.error))

        response = parse_result.value
        entries_list: list[t.GeneralValueType] = list(response.entries)
        return r[list[t.GeneralValueType]].ok(entries_list)

    def _parse_file(
        self,
        path: Path,
        *,
        server_type: str | None = None,
    ) -> r[list[t.GeneralValueType]]:
        """Parse LDIF file (internal helper)."""
        if not path.exists():
            return r[list[t.GeneralValueType]].fail(f"File not found: {path}")

        try:
            content = path.read_text(encoding="utf-8")
        except OSError as e:
            return r[list[t.GeneralValueType]].fail(f"Failed to read file: {e}")

        return self.parse(content, server_type=server_type)

    def create_entry(
        self,
        dn: str,
        attributes: dict[str, str | list[str]],
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
        if isinstance(ldif_content, Path):
            try:
                content_str = ldif_content.read_text(encoding="utf-8")
            except OSError as e:
                return r[m.Ldif.LdifResults.ServerDetectionResult].fail(
                    f"Failed to read file: {e}"
                )
        else:
            content_str = ldif_content
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
        entries: list[t.GeneralValueType],
        *,
        server_type: str | None = None,
    ) -> r[str]:
        """Write entries to LDIF format string."""
        entries_typed: list[m.Ldif.Entry] = []
        for entry in entries:
            if isinstance(entry, m.Ldif.Entry):
                entries_typed.append(entry)
            elif isinstance(entry, BaseModel):
                entry_json = entry.model_dump_json()
                entries_typed.append(m.Ldif.Entry.model_validate_json(entry_json))
            else:
                entries_typed.append(m.Ldif.Entry.model_validate(entry))

        effective_type = server_type or self._get_effective_server_type_value()
        server_type_typed: str | None = (
            str(effective_type) if effective_type is not None else None
        )
        return self.writer.write_to_string(
            entries_typed,
            server_type=server_type_typed,
        )

    def write_file(
        self,
        entries: list[t.GeneralValueType],
        path: Path,
        *,
        server_type: str | None = None,
    ) -> r[bool]:
        """Write entries to LDIF file."""
        write_result = self.write(entries, server_type=server_type)
        if write_result.is_failure:
            return r[bool].fail(str(write_result.error))

        content = write_result.value
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")
            return r[bool].ok(True)
        except OSError as e:
            return r[bool].fail(f"Failed to write file: {e}")

    def validate_entries(
        self,
        entries: list[t.GeneralValueType],
    ) -> r[m.Ldif.Results.ValidationResult]:
        """Validate list of entries."""
        entries_typed: list[m.Ldif.Entry] = []
        for entry in entries:
            if isinstance(entry, m.Ldif.Entry):
                entries_typed.append(entry)
            elif isinstance(entry, dict):
                entries_typed.append(m.Ldif.Entry.model_validate(entry))
            else:
                entries_typed.append(m.Ldif.Entry.model_validate(entry))

        validation_service = FlextLdifValidation()
        return FlextLdifAnalysis.validate_entries(
            entries_typed,
            validation_service,
        )

    def filter_entries(
        self,
        entries: list[t.GeneralValueType],
        filter_func: p.Ldif.PredicateProtocol[t.GeneralValueType],
    ) -> r[list[t.GeneralValueType]]:
        """Filter entries using predicate function."""
        try:
            filtered = [entry for entry in entries if filter_func(entry)]
            return r[list[t.GeneralValueType]].ok(filtered)
        except Exception as e:
            return r[list[t.GeneralValueType]].fail(f"Filter error: {e}")

    def get_entry_statistics(
        self,
        _entries: list[object],
    ) -> r[m.Ldif.Results.EntriesStatistics]:
        """Get statistics for list of entries."""
        entries_typed: list[m.Ldif.Entry] = []
        for entry in _entries:
            if isinstance(entry, m.Ldif.Entry):
                entries_typed.append(entry)
            elif isinstance(entry, dict):
                entries_typed.append(m.Ldif.Entry.model_validate(entry))
            else:
                entries_typed.append(m.Ldif.Entry.model_validate(entry))

        stats_service = FlextLdifStatistics()
        return stats_service.calculate_for_entries(entries_typed)

    def filter_persons(
        self,
        entries: list[t.GeneralValueType],
    ) -> r[list[t.GeneralValueType]]:
        """Filter entries to only person entries."""
        person_classes = {"person", "inetorgperson", "organizationalperson"}

        class IsPersonPredicate:
            """Predicate class matching Protocol[T].__call__ signature."""

            def __call__(self, item: t.GeneralValueType) -> bool:
                """Check if entry is a person object class."""
                entry = item
                if entry is None:
                    return False
                if isinstance(entry, dict):
                    objectclasses = entry.get("objectClass", [])
                elif isinstance(entry, m.Ldif.Entry):
                    attrs = entry.attributes
                    if attrs is None:
                        return False
                    if isinstance(attrs, dict):
                        objectclasses = attrs.get("objectClass", [])
                    else:
                        return False
                else:
                    return False

                if isinstance(objectclasses, str):
                    objectclasses_list: list[str] = [objectclasses]
                elif isinstance(objectclasses, list):
                    objectclasses_list = [str(oc) for oc in objectclasses]
                else:
                    return False

                return any(oc.lower() in person_classes for oc in objectclasses_list)

        return self.filter_entries(entries, IsPersonPredicate())

    def execute(self) -> r[object]:
        """Execute service health check for FlextService pattern compliance."""
        try:
            _ = self.parser
            _ = self.writer
            _ = self.detector

            health_entry = m.Ldif.Entry.model_validate({
                "dn": "cn=health-check",
                "attributes": {"cn": ["health-check"]},
            })
            return r[object].ok(health_entry)
        except Exception as e:
            return r[object].fail(f"Health check failed: {e}")


__all__ = ["FlextLdif"]
