"""FLEXT-LDIF API - Unified Facade for LDIF Operations."""

from __future__ import annotations

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


class FlextLdif(FlextLdifServiceBase[object]):
    """Main API facade for LDIF operations using composition pattern."""

    _instance: ClassVar[FlextLdif | None] = None
    _init_config_overrides: ClassVar[dict[str, t.FlexibleValue] | None] = None
    _service_cache: dict[str, t.GeneralValueType]

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
                type(self)._init_config_overrides = config.model_dump(
                    exclude_none=True,
                )
            super().__init__()
        finally:
            type(self)._init_config_overrides = None

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
        output_filename_raw = kwargs.get("output_filename")
        output_filename: str | None = (
            output_filename_raw if isinstance(output_filename_raw, str) else None
        )
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
        source: str | Path,
        *,
        server_type: str | None = None,
    ) -> r[list[t.GeneralValueType]]:
        """Parse LDIF content from string or file."""
        effective_type = server_type or self._get_effective_server_type_value()

        if isinstance(source, Path):
            return self._parse_file(source, server_type=effective_type)

        parse_result = self.parser.parse_string(
            source,
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

        return self.parse(source=content, server_type=server_type)

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
        format_options: (
            m.Ldif.LdifResults.WriteFormatOptions
            | m.Ldif.LdifResults.WriteOptions
            | dict[str, t.GeneralValueType]
            | None
        ) = None,
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
            format_options=format_options,
        )

    def write_file(
        self,
        entries: list[t.GeneralValueType],
        path: Path,
        *,
        server_type: str | None = None,
        format_options: (
            m.Ldif.LdifResults.WriteFormatOptions
            | m.Ldif.LdifResults.WriteOptions
            | dict[str, t.GeneralValueType]
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
            path.write_text(content, encoding="utf-8")
            return r[bool].ok(value=True)
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

    def filter(
        self,
        entries: list[t.GeneralValueType],
        *,
        objectclass: str | None = None,
        dn_pattern: str | None = None,
        attributes: dict[str, object] | None = None,
    ) -> r[list[t.GeneralValueType]]:
        """Filter entries by objectClass, DN pattern and attribute criteria."""
        entries_typed: list[m.Ldif.Entry] = []
        for entry in entries:
            if isinstance(entry, m.Ldif.Entry):
                entries_typed.append(entry)
            elif isinstance(entry, dict):
                entries_typed.append(m.Ldif.Entry.model_validate(entry))
            else:
                entries_typed.append(m.Ldif.Entry.model_validate(entry))

        if not objectclass and not dn_pattern and not attributes:
            return r[list[t.GeneralValueType]].ok(list(entries_typed))

        required_attrs: list[str] = list(attributes.keys()) if attributes else []
        filtered: list[m.Ldif.Entry] = []
        for entry in entries_typed:
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
                    expected_values: list[str] = (
                        [str(v) for v in expected]
                        if isinstance(expected, list)
                        else [str(expected)]
                    )
                    existing_values = [str(v) for v in entry_values]
                    if not any(value in existing_values for value in expected_values):
                        matches_values = False
                        break
                if not matches_values:
                    continue

            filtered.append(entry)

        return r[list[t.GeneralValueType]].ok(filtered)

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
