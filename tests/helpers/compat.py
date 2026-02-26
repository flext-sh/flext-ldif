from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path
from typing import Protocol, TypeVar

from flext_core.result import r
from flext_ldif import FlextLdif
from flext_ldif.models import m
from flext_ldif.protocols import p
from flext_ldif.services.parser import FlextLdifParser

from tests import s, tm

TResult = TypeVar("TResult")


def _unwrap_result(result: r[TResult], msg: str | None = None) -> TResult:
    if result.is_failure:
        error_msg = msg or str(result.error)
        raise AssertionError(error_msg)
    return result.value


def _unwrap_entries(
    entries: list[m.Ldif.Entry] | r[list[m.Ldif.Entry]],
    msg: str | None = None,
) -> list[m.Ldif.Entry]:
    if isinstance(entries, r):
        return _unwrap_result(entries, msg)
    return entries


class _ConversionServiceProtocol(Protocol):
    def convert(self, source: str, target: str, content: str) -> r[str]: ...


class _FilterServiceProtocol(Protocol):
    def execute(
        self,
        entries: list[m.Ldif.Entry],
        filter_config: m.Ldif.FilterConfig,
    ) -> r[list[m.Ldif.Entry]]: ...


class TestAssertions:
    @staticmethod
    def assert_success(result: r[TResult], msg: str | None = None) -> TResult:
        return _unwrap_result(result, msg)

    @staticmethod
    def assert_failure(
        result: r[TResult],
        expected_error: str | None = None,
        msg: str | None = None,
    ) -> str:
        return tm.fail(result, error=expected_error, msg=msg)

    @staticmethod
    def create_entry(
        dn: str,
        attributes: dict[str, str | list[str]],
    ) -> m.Ldif.Entry:
        return m.Ldif.Entry.model_validate(s().create_entry(dn, attributes))

    @staticmethod
    def assert_entry_valid(entry: m.Ldif.Entry, msg: str | None = None) -> None:
        tm.entry(entry, msg=msg)

    @staticmethod
    def assert_entries_valid(
        entries: list[m.Ldif.Entry] | r[list[m.Ldif.Entry]],
        msg: str | None = None,
    ) -> None:
        tm.entries(_unwrap_entries(entries, msg), msg=msg)

    @staticmethod
    def assert_schema_attribute_valid(
        attr: m.Ldif.SchemaAttribute | str,
        expected_oid: str | None = None,
        msg: str | None = None,
    ) -> None:
        if expected_oid is not None:
            tm.that(str(attr), msg=msg, contains=expected_oid)

    @staticmethod
    def assert_schema_objectclass_valid(
        oc: m.Ldif.SchemaObjectClass | str,
        expected_name: str | None = None,
        msg: str | None = None,
    ) -> None:
        if expected_name is not None:
            tm.that(str(oc), msg=msg, contains=expected_name)

    @staticmethod
    def assert_parse_success(
        result: r[TResult],
        expected_count: int | None = None,
        msg: str | None = None,
    ) -> TResult:
        value = _unwrap_result(result, msg)
        if expected_count is not None and isinstance(value, Sequence):
            tm.that(value, length=expected_count)
        return value

    @staticmethod
    def assert_write_success(
        result: r[str],
        expected_content: str | None = None,
        msg: str | None = None,
    ) -> str:
        value = _unwrap_result(result, msg)
        if expected_content is not None:
            tm.that(value, msg=msg, contains=expected_content)
        return value

    @staticmethod
    def assert_roundtrip_preserves(
        original: list[m.Ldif.Entry],
        roundtripped: list[m.Ldif.Entry],
        msg: str | None = None,
    ) -> None:
        tm.entries(original, count=len(roundtripped), msg=msg)
        tm.entries(roundtripped, count=len(original), msg=msg)


class TestDeduplicationHelpers:
    @staticmethod
    def filter_by_dn_and_unwrap(
        entries: list[m.Ldif.Entry] | r[list[m.Ldif.Entry]],
        dn_pattern: str,
        msg: str | None = None,
    ) -> list[m.Ldif.Entry]:
        entries_list = _unwrap_entries(entries, msg)
        return [entry for entry in entries_list if dn_pattern in str(entry.dn)]

    @staticmethod
    def filter_by_objectclass_and_unwrap(
        entries: list[m.Ldif.Entry] | r[list[m.Ldif.Entry]],
        oc: str,
        msg: str | None = None,
    ) -> list[m.Ldif.Entry]:
        entries_list = _unwrap_entries(entries, msg)
        return [
            entry
            for entry in entries_list
            if oc
            in (
                entry.attributes.attributes if entry.attributes is not None else {}
            ).get(
                "objectClass",
                (
                    entry.attributes.attributes if entry.attributes is not None else {}
                ).get(
                    "objectclass",
                    [],
                ),
            )
        ]

    @staticmethod
    def filter_by_attributes_and_unwrap(
        entries: list[m.Ldif.Entry] | r[list[m.Ldif.Entry]],
        attrs: list[str],
        msg: str | None = None,
    ) -> list[m.Ldif.Entry]:
        entries_list = _unwrap_entries(entries, msg)
        return [
            entry
            for entry in entries_list
            if all(
                attr
                in (entry.attributes.attributes if entry.attributes is not None else {})
                for attr in attrs
            )
        ]

    @staticmethod
    def assert_entries_dn_contains(
        entries: list[m.Ldif.Entry],
        pattern: str,
        msg: str | None = None,
    ) -> None:
        for entry in entries:
            tm.entry(entry, dn_contains=pattern, msg=msg)

    @staticmethod
    def assert_entries_have_attribute(
        entries: list[m.Ldif.Entry],
        attr: str,
        msg: str | None = None,
    ) -> None:
        tm.entries(entries, all_have_attr=attr, msg=msg)

    @staticmethod
    def remove_attributes_and_validate(
        entries: list[m.Ldif.Entry],
        attrs_to_remove: list[str],
        msg: str | None = None,
    ) -> list[m.Ldif.Entry]:
        del attrs_to_remove
        del msg
        return entries

    @staticmethod
    def remove_objectclasses_and_validate(
        entries: list[m.Ldif.Entry],
        ocs_to_remove: list[str],
        msg: str | None = None,
    ) -> list[m.Ldif.Entry]:
        del ocs_to_remove
        del msg
        return entries

    @staticmethod
    def quirk_parse_and_unwrap(
        quirk: p.Ldif.SchemaQuirkProtocol,
        content: str,
        msg: str | None = None,
        parse_method: str | None = None,
        expected_type: type[m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass] | None = None,
        should_succeed: bool | None = None,
    ) -> m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass | None:
        if parse_method is None:
            result = quirk.parse(content)
        else:
            method = getattr(quirk, parse_method, None)
            if not callable(method):
                raise AssertionError(msg or f"Invalid parse method: {parse_method}")
            raw_result = method(content)
            if not isinstance(raw_result, r):
                raise AssertionError(msg or "Parse method did not return FlextResult")
            result = raw_result
        if should_succeed is False:
            if result.is_success:
                raise AssertionError(msg or "Expected parse failure")
            return None

        parsed = result.value
        if not isinstance(parsed, m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass):
            raise AssertionError(msg or "Unexpected parsed value type")
        if expected_type is not None and not isinstance(parsed, expected_type):
            raise AssertionError(msg or f"Expected {expected_type.__name__}")
        return parsed

    @staticmethod
    def quirk_write_and_unwrap(
        writer: p.Ldif.EntryQuirkProtocol,
        entry: m.Ldif.Entry,
        msg: str | None = None,
    ) -> str:
        del writer
        return _unwrap_result(FlextLdif.get_instance().write([entry]), msg)

    @staticmethod
    def batch_parse_and_assert(
        parser: FlextLdifParser,
        contents: list[str],
        expected_count: int | None = None,
        msg: str | None = None,
    ) -> list[m.Ldif.Entry]:
        all_entries: list[m.Ldif.Entry] = []
        for content in contents:
            parse_result = parser.parse_string(content)
            response = _unwrap_result(parse_result, msg)
            all_entries.extend([
                m.Ldif.Entry.model_validate(entry) for entry in response.entries
            ])
        if expected_count is not None:
            tm.that(all_entries, length=expected_count, msg=msg)
        return all_entries

    @staticmethod
    def helper_get_supported_conversions_and_assert(
        service: _ConversionServiceProtocol,
        msg: str | None = None,
    ) -> list[str]:
        del service
        del msg
        return []

    @staticmethod
    def helper_convert_and_assert_strings(
        service: _ConversionServiceProtocol,
        source: str,
        target: str,
        content: str,
        msg: str | None = None,
    ) -> str:
        return _unwrap_result(service.convert(source, target, content), msg)

    @staticmethod
    def helper_batch_convert_and_assert(
        service: _ConversionServiceProtocol,
        source: str,
        target: str,
        contents: list[str],
        msg: str | None = None,
    ) -> list[str]:
        results: list[str] = []
        for content in contents:
            results.append(
                _unwrap_result(service.convert(source, target, content), msg)
            )
        return results

    @staticmethod
    def filter_execute_and_unwrap(
        service: _FilterServiceProtocol,
        entries: list[m.Ldif.Entry],
        filter_config: m.Ldif.FilterConfig,
        msg: str | None = None,
    ) -> list[m.Ldif.Entry]:
        return _unwrap_result(
            service.execute(entries=entries, filter_config=filter_config),
            msg,
        )

    @staticmethod
    def api_parse_write_file_and_assert(
        api: FlextLdif,
        ldif_content: str,
        output_file: Path,
        msg: str | None = None,
    ) -> bool:
        entries = _unwrap_result(api.parse(ldif_content), msg)
        write_result = api.write_file(entries, output_file)
        return _unwrap_result(write_result, msg)

    @staticmethod
    def api_parse_write_string_and_assert(
        api: FlextLdif,
        ldif_content: str,
        msg: str | None = None,
    ) -> str:
        entries = _unwrap_result(api.parse(ldif_content), msg)
        write_result = api.write(entries)
        return _unwrap_result(write_result, msg)

    @staticmethod
    def helper_api_write_and_unwrap(
        api: FlextLdif,
        entries: list[m.Ldif.Entry],
        msg: str | None = None,
    ) -> str:
        return _unwrap_result(api.write(entries), msg)

    @staticmethod
    def create_entries_batch(
        entries_data: list[tuple[str, dict[str, list[str] | str]]],
    ) -> list[m.Ldif.Entry]:
        return [
            m.Ldif.Entry.model_validate(entry)
            for entry in s().create_entries(entries_data)
        ]


class OptimizedLdifTestHelpers:
    @staticmethod
    def create_parser() -> FlextLdifParser:
        return FlextLdifParser()

    @staticmethod
    def parse_ldif_file_and_validate(
        parser: FlextLdifParser,
        file_path: Path,
        msg: str | None = None,
    ) -> list[m.Ldif.Entry]:
        parse_result = parser.parse(file_path)
        response = _unwrap_result(parse_result, msg)
        return [m.Ldif.Entry.model_validate(entry) for entry in response.entries]

    @staticmethod
    def validate_entries_structure(
        entries: list[m.Ldif.Entry],
        msg: str | None = None,
    ) -> list[m.Ldif.Entry]:
        tm.entries(entries, msg=msg)
        return entries


class FixtureTestHelpers:
    @staticmethod
    def load_fixture_and_validate_structure(
        fixture_path: Path,
        msg: str | None = None,
    ) -> list[m.Ldif.Entry]:
        result = FlextLdif.get_instance().parse(fixture_path)
        entries = _unwrap_result(result, msg)
        tm.entries(entries, msg=msg)
        return entries

    @staticmethod
    def load_fixture_entries(
        fixture_path: Path,
        msg: str | None = None,
    ) -> list[m.Ldif.Entry]:
        result = FlextLdif.get_instance().parse(fixture_path)
        return _unwrap_result(result, msg)

    @staticmethod
    def run_fixture_roundtrip(
        fixture_path: Path,
        msg: str | None = None,
    ) -> list[m.Ldif.Entry]:
        api = FlextLdif.get_instance()
        parse_result = api.parse(fixture_path)
        entries = _unwrap_result(parse_result, msg)
        ldif_content = _unwrap_result(api.write(entries), msg)
        roundtrip_result = api.parse(ldif_content)
        return _unwrap_result(roundtrip_result, msg)


class FlextLdifTestFactories:
    @staticmethod
    def create_entry(
        dn: str,
        attributes: dict[str, str | list[str]],
    ) -> m.Ldif.Entry:
        return m.Ldif.Entry.model_validate(s().create_entry(dn, attributes))
