"""Test utilities facade with shared helper re-exports."""

from __future__ import annotations

import fcntl
import os
import types
import uuid
from collections.abc import Mapping, MutableMapping, Sequence
from pathlib import Path
from typing import ClassVar, TextIO

from flext_ldap import u
from flext_tests import FlextTestsUtilities, tk

from flext_core import FlextLogger
from tests import c, m, p, t


class TestsFlextLdifUtilities(FlextTestsUtilities, u):
    """Project test utility namespace extension."""

    class Ldif(u.Ldif):
        """LDIF test utility namespace."""

        class Tests:
            """Flat test utility namespace for flext-ldif."""

            Docker = tk
            LdapConnectionLike = p.Ldap.Ldap3Connection
            LdapEntryLike = p.Ldap.Ldap3Entry

            _logger: ClassVar[FlextLogger] = u.fetch_logger(__name__)
            _resolved_admin_credentials: ClassVar[list[tuple[str, str] | None]] = [
                None,
            ]
            _fixture_cache: ClassVar[
                MutableMapping[
                    tuple[t.Ldif.Tests.FixtureServer, t.Ldif.Tests.FixtureKind],
                    str,
                ]
            ] = {}
            _fixture_metadata_cache: ClassVar[
                MutableMapping[Path, m.Ldif.Tests.FixtureMetadata]
            ] = {}

            @staticmethod
            def create_server_from_url(
                server_url: str,
                *,
                get_info: t.Ldap.Ldap3GetInfo = "ALL",
            ) -> p.Ldap.Ldap3Server:
                """Create an LDAP server from a URL for test connectivity checks."""
                return u.Ldap.create_server_from_url(server_url, get_info=get_info)

            @staticmethod
            def create_bare_server(
                host: str,
                *,
                port: int = c.Ldif.Tests.DOCKER_PORT,
                get_info: t.Ldap.Ldap3GetInfo = "NO_INFO",
            ) -> p.Ldap.Ldap3Server:
                """Create a minimal LDAP server for connectivity checks."""
                return u.Ldap.create_server_from_url(
                    f"ldap://{host}:{port}",
                    get_info=get_info,
                )

            @staticmethod
            def create_connection(
                server: p.Ldap.Ldap3Server,
                *,
                user: str,
                password: str,
                auto_bind: bool = True,
                receive_timeout: int | None = None,
            ) -> p.Ldap.Ldap3Connection:
                """Create an LDAP connection for test workflows."""
                if receive_timeout is None:
                    return u.Ldap.create_connection(
                        server,
                        user=user,
                        password=password,
                        auto_bind=auto_bind,
                    )
                return u.Ldap.create_connection(
                    server,
                    user=user,
                    password=password,
                    auto_bind=auto_bind,
                    receive_timeout=receive_timeout,
                )

            @staticmethod
            def create_real_entry(
                dn: str | None = None,
                attributes: Mapping[str, Sequence[str]] | None = None,
                server_type: str = "generic",
            ) -> m.Ldif.Entry:
                """Create a real Entry model with valid data."""
                entry_id = uuid.uuid4().hex[:8]
                actual_dn = dn or f"cn=test-{entry_id},ou=users,dc=example,dc=com"
                actual_attributes = attributes or {
                    "cn": [f"test-{entry_id}"],
                    "sn": ["Test"],
                    "mail": [f"test-{entry_id}@example.com"],
                    "objectClass": [
                        "person",
                        "organizationalPerson",
                        "inetOrgPerson",
                    ],
                }
                return m.Ldif.Entry.model_validate(
                    {
                        "dn": {"value": actual_dn},
                        "attributes": {
                            "attributes": {
                                key: list(values)
                                for key, values in actual_attributes.items()
                            },
                        },
                        "server_type": server_type,
                    },
                )

            @staticmethod
            def create_real_ldif_content(
                entries_count: int = 3,
                *,
                include_schema: bool = False,
            ) -> str:
                """Create real LDIF content for testing."""
                lines: list[str] = []
                if include_schema:
                    lines.extend(
                        [
                            "dn: cn=schema",
                            "objectClass: top",
                            "objectClass: ldapSubentry",
                            "objectClass: subschema",
                            "",
                            "attributeTypes: ( 2.5.4.3 NAME 'cn' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
                            "",
                        ],
                    )
                for index in range(entries_count):
                    entry_id = uuid.uuid4().hex[:8]
                    lines.extend(
                        [
                            f"dn: cn=user-{entry_id},ou=users,dc=example,dc=com",
                            "objectClass: person",
                            "objectClass: organizationalPerson",
                            "objectClass: inetOrgPerson",
                            f"cn: User {entry_id}",
                            f"sn: Test{index}",
                            f"mail: user{entry_id}@example.com",
                            "",
                        ],
                    )
                return "\n".join(lines)

            @staticmethod
            def parametrize_real_data() -> Sequence[m.Ldif.Tests.LdifTestData]:
                """Generate parametrized test data for comprehensive coverage."""
                server_types = (
                    "generic",
                    c.Ldif.Tests.OPENLDAP,
                    c.Ldif.Tests.AD,
                    c.Ldif.Tests.OID,
                    c.Ldif.Tests.OUD,
                )
                return [
                    m.Ldif.Tests.LdifTestData(
                        id=f"entry_{server_type}",
                        server_type=server_type,
                        dn=f"cn=test-{server_type},ou=users,dc=example,dc=com",
                        attributes={
                            "cn": [f"test-{server_type}"],
                            "objectClass": ["person", "organizationalPerson"],
                        },
                    )
                    for server_type in server_types
                ]

            class FileLock:
                """File-based locking for pytest-xdist parallel test isolation."""

                def __init__(self, lock_file: Path) -> None:
                    self.lock_file = lock_file
                    self._fd: int | None = None
                    self._file_obj: TextIO | None = None

                def __enter__(self) -> None:
                    """Acquire exclusive file lock."""
                    self.lock_file.parent.mkdir(parents=True, exist_ok=True)
                    self._file_obj = self.lock_file.open("w")
                    self._fd = self._file_obj.fileno()
                    fcntl.flock(self._fd, fcntl.LOCK_EX)

                def __exit__(
                    self,
                    exc_type: type[BaseException] | None,
                    exc_val: BaseException | None,
                    exc_tb: types.TracebackType | None,
                ) -> None:
                    """Release file lock and clean up."""
                    if self._fd is not None:
                        fcntl.flock(self._fd, fcntl.LOCK_UN)
                    if self._file_obj is not None:
                        self._file_obj.close()
                    self.lock_file.unlink(missing_ok=True)

            @staticmethod
            def fixture_path(
                server_type: t.Ldif.Tests.FixtureServer,
                fixture_type: t.Ldif.Tests.FixtureKind,
            ) -> Path:
                """Return the canonical path for a fixture file."""
                server_dir = c.Ldif.Tests.FIXTURES_DIR / server_type
                file_path = server_dir / f"{server_type}_{fixture_type}_fixtures.ldif"
                if not file_path.exists():
                    msg = f"Fixture file not found: {file_path}"
                    raise FileNotFoundError(msg)
                return file_path

            @classmethod
            def load_fixture(
                cls,
                server_type: t.Ldif.Tests.FixtureServer,
                fixture_type: t.Ldif.Tests.FixtureKind,
            ) -> str:
                """Load one fixture file with caching."""
                cache_key = (server_type, fixture_type)
                if cache_key not in cls._fixture_cache:
                    file_path = cls.fixture_path(server_type, fixture_type)
                    cls._fixture_cache[cache_key] = file_path.read_text(
                        encoding="utf-8"
                    )
                return cls._fixture_cache[cache_key]

            @classmethod
            def load_server_fixtures(
                cls,
                server_type: t.Ldif.Tests.FixtureServer,
            ) -> Mapping[t.Ldif.Tests.FixtureKind, str]:
                """Load all available fixtures for a server type."""
                fixture_types: tuple[t.Ldif.Tests.FixtureKind, ...] = (
                    c.Ldif.Tests.SCHEMA,
                    c.Ldif.Tests.ACL,
                    c.Ldif.Tests.ENTRIES,
                    c.Ldif.Tests.INTEGRATION,
                )
                return {
                    fixture_type: cls.load_fixture(server_type, fixture_type)
                    for fixture_type in fixture_types
                    if cls.fixture_exists(server_type, fixture_type)
                }

            @classmethod
            def available_fixture_servers(cls) -> Sequence[t.Ldif.Tests.FixtureServer]:
                """Return the server types that currently have fixture directories."""
                server_types: tuple[t.Ldif.Tests.FixtureServer, ...] = (
                    c.Ldif.Tests.OID,
                    c.Ldif.Tests.OUD,
                    c.Ldif.Tests.OPENLDAP,
                    c.Ldif.Tests.OPENLDAP1,
                    c.Ldif.Tests.DS389,
                    c.Ldif.Tests.APACHE,
                    c.Ldif.Tests.NOVELL,
                    c.Ldif.Tests.TIVOLI,
                    c.Ldif.Tests.AD,
                    c.Ldif.Tests.RFC,
                )
                return tuple(
                    server_type
                    for server_type in server_types
                    if (c.Ldif.Tests.FIXTURES_DIR / server_type).is_dir()
                )

            @classmethod
            def available_fixture_types(
                cls,
                server_type: t.Ldif.Tests.FixtureServer,
            ) -> Sequence[t.Ldif.Tests.FixtureKind]:
                """Return the fixture kinds available for one server type."""
                fixture_types: tuple[t.Ldif.Tests.FixtureKind, ...] = (
                    c.Ldif.Tests.SCHEMA,
                    c.Ldif.Tests.ACL,
                    c.Ldif.Tests.ENTRIES,
                    c.Ldif.Tests.INTEGRATION,
                )
                return tuple(
                    fixture_type
                    for fixture_type in fixture_types
                    if cls.fixture_exists(server_type, fixture_type)
                )

            @classmethod
            def fixture_exists(
                cls,
                server_type: t.Ldif.Tests.FixtureServer,
                fixture_type: t.Ldif.Tests.FixtureKind,
            ) -> bool:
                """Return whether a fixture exists."""
                try:
                    cls.fixture_path(server_type, fixture_type)
                except FileNotFoundError:
                    return False
                return True

            @classmethod
            def fixture_metadata(
                cls,
                server_type: t.Ldif.Tests.FixtureServer,
                fixture_type: t.Ldif.Tests.FixtureKind,
            ) -> m.Ldif.Tests.FixtureMetadata:
                """Return metadata for one fixture file."""
                file_path = cls.fixture_path(server_type, fixture_type)
                if file_path in cls._fixture_metadata_cache:
                    return cls._fixture_metadata_cache[file_path]
                content = cls.load_fixture(server_type, fixture_type)
                lines = content.splitlines()
                metadata = m.Ldif.Tests.FixtureMetadata(
                    server_type=server_type,
                    fixture_type=fixture_type,
                    file_path=file_path,
                    line_count=len(lines),
                    entry_count=sum(
                        1 for line in lines if line.strip().startswith("dn:")
                    ),
                    size_bytes=file_path.stat().st_size,
                )
                cls._fixture_metadata_cache[file_path] = metadata
                return metadata

            @staticmethod
            def get_docker_control(worker_id: str = "master") -> tk:
                """Create Docker test infrastructure controller."""
                return tk(
                    workspace_root=c.Ldif.Tests.PROJECT_ROOT,
                    worker_id=worker_id,
                )

            @classmethod
            def get_admin_credentials(cls) -> tuple[str, str]:
                """Resolve LDAP admin credentials, preferring a working pair."""
                cache = cls._resolved_admin_credentials
                if cache[0] is not None:
                    return cache[0]
                env_dn = os.getenv("FLEXT_LDAP_BIND_DN")
                env_password = os.getenv("FLEXT_LDAP_BIND_PASSWORD")
                candidates: list[tuple[str, str]] = []
                if env_dn and env_password:
                    candidates.append((env_dn, env_password))
                candidates.extend(
                    [
                        (
                            c.Ldif.Tests.DOCKER_ADMIN_DN,
                            c.Ldif.Tests.DOCKER_ADMIN_PASSWORD,
                        ),
                        (
                            c.Ldif.Tests.DOCKER_LEGACY_ADMIN_DN,
                            c.Ldif.Tests.DOCKER_LEGACY_ADMIN_PASSWORD,
                        ),
                    ],
                )
                for candidate_dn, candidate_password in candidates:
                    try:
                        server = cls.create_bare_server(
                            "localhost",
                            port=c.Ldif.Tests.DOCKER_PORT,
                            get_info="NO_INFO",
                        )
                        connection = cls.create_connection(
                            server,
                            user=candidate_dn,
                            password=candidate_password,
                            auto_bind=True,
                            receive_timeout=1,
                        )
                        if connection.bound:
                            connection.unbind()
                            resolved = (candidate_dn, candidate_password)
                            cache[0] = resolved
                            return resolved
                    except (
                        ConnectionError,
                        OSError,
                        ValueError,
                        t.Ldap.LDAPException,
                    ):
                        continue
                fallback = (
                    c.Ldif.Tests.DOCKER_ADMIN_DN,
                    c.Ldif.Tests.DOCKER_ADMIN_PASSWORD,
                )
                cache[0] = fallback
                return fallback

            @staticmethod
            def assert_quirk_schema_parse_and_properties(
                quirk: p.Ldif.SchemaQuirk,
                schema_def: str,
                *,
                expected_oid: str | None = None,
                expected_name: str | None = None,
                expected_desc: str | None = None,
                expected_syntax: str | None = None,
                expected_single_value: bool | None = None,
                expected_length: int | None = None,
                expected_kind: str | None = None,
                expected_sup: str | None = None,
                expected_must: t.StrSequence | None = None,
                expected_may: t.StrSequence | None = None,
            ) -> m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass:
                """Parse schema content and assert the expected properties."""
                is_objectclass = any(
                    kind in schema_def
                    for kind in (
                        c.Ldif.Tests.SCHEMA_STRUCTURAL,
                        c.Ldif.Tests.SCHEMA_AUXILIARY,
                        c.Ldif.Tests.SCHEMA_ABSTRACT,
                    )
                )
                result = (
                    quirk.parse_objectclass(schema_def)
                    if is_objectclass
                    else quirk.parse_attribute(schema_def)
                )
                if result.failure:
                    msg = f"Parsing failed: {result.error}"
                    raise AssertionError(msg)
                value = (
                    m.Ldif.SchemaObjectClass.model_validate(result.value)
                    if is_objectclass
                    else m.Ldif.SchemaAttribute.model_validate(result.value)
                )
                if expected_oid is not None and value.oid != expected_oid:
                    raise AssertionError(
                        f"Expected OID '{expected_oid}', got '{value.oid}'",
                    )
                if expected_name is not None and value.name != expected_name:
                    raise AssertionError(
                        f"Expected NAME '{expected_name}', got '{value.name}'",
                    )
                if isinstance(value, m.Ldif.SchemaAttribute):
                    if expected_desc is not None and value.desc != expected_desc:
                        raise AssertionError(
                            f"Expected DESC '{expected_desc}', got '{value.desc}'",
                        )
                    if expected_syntax is not None and value.syntax != expected_syntax:
                        raise AssertionError(
                            f"Expected SYNTAX '{expected_syntax}', got '{value.syntax}'",
                        )
                    if (
                        expected_single_value is not None
                        and value.single_value != expected_single_value
                    ):
                        raise AssertionError(
                            f"Expected SINGLE-VALUE {expected_single_value}, got '{value.single_value}'",
                        )
                    if expected_length is not None and value.length != expected_length:
                        raise AssertionError(
                            f"Expected length {expected_length}, got '{value.length}'",
                        )
                    return value
                if expected_desc is not None and value.desc != expected_desc:
                    raise AssertionError(
                        f"Expected DESC '{expected_desc}', got '{value.desc}'",
                    )
                if expected_kind is not None and value.kind != expected_kind:
                    raise AssertionError(
                        f"Expected KIND '{expected_kind}', got '{value.kind}'",
                    )
                if expected_sup is not None and value.sup != expected_sup:
                    raise AssertionError(
                        f"Expected SUP '{expected_sup}', got '{value.sup}'",
                    )
                if expected_must is not None and list(value.must or []) != list(
                    expected_must,
                ):
                    raise AssertionError(
                        f"Expected MUST {expected_must}, got {value.must}",
                    )
                if expected_may is not None and list(value.may or []) != list(
                    expected_may,
                ):
                    raise AssertionError(
                        f"Expected MAY {expected_may}, got {value.may}",
                    )
                return value

            @staticmethod
            def quirk_parse_and_unwrap(
                quirk: (p.Ldif.SchemaQuirk | p.Ldif.Tests.ParseInputQuirk),
                content: str,
                *,
                parse_method: t.Ldif.Tests.ParseMethod = "parse_quirk",
                expected_type: (
                    type[m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass | m.Ldif.Acl]
                    | None
                ) = None,
                should_succeed: bool | None = None,
                message: str | None = None,
            ) -> m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass | m.Ldif.Acl | None:
                """Parse content with a quirk and unwrap the typed result."""
                if parse_method == "parse_attribute":
                    if not isinstance(quirk, p.Ldif.SchemaQuirk):
                        msg = "parse_attribute requires a schema quirk"
                        raise AssertionError(msg)
                    result = quirk.parse_attribute(content)
                elif parse_method == "parse_objectclass":
                    if not isinstance(quirk, p.Ldif.SchemaQuirk):
                        msg = "parse_objectclass requires a schema quirk"
                        raise AssertionError(
                            msg,
                        )
                    result = quirk.parse_objectclass(content)
                elif parse_method == "parse_input":
                    if not isinstance(quirk, p.Ldif.Tests.ParseInputQuirk):
                        msg = "parse_input is not supported by this quirk"
                        raise AssertionError(msg)
                    result = quirk.parse_input(content)
                else:
                    msg = f"{parse_method} is not supported by this quirk"
                    raise AssertionError(msg)
                if should_succeed is False:
                    if result.success:
                        msg = message or "Expected failure but parse succeeded"
                        raise AssertionError(msg)
                    return None
                if result.failure:
                    msg = (
                        message or f"Expected success but parse failed: {result.error}"
                    )
                    raise AssertionError(msg)
                value = result.value
                if expected_type is not None and not isinstance(value, expected_type):
                    raise AssertionError(
                        f"Expected {expected_type.__name__}, got {type(value).__name__}",
                    )
                return (
                    value
                    if isinstance(
                        value,
                        (
                            m.Ldif.SchemaAttribute,
                            m.Ldif.SchemaObjectClass,
                            m.Ldif.Acl,
                        ),
                    )
                    else None
                )

            @staticmethod
            def acl_parse_and_unwrap(
                quirk: p.Ldif.Tests.ParseAclQuirk,
                content: str,
                *,
                expected_type: type[m.Ldif.Acl] | None = None,
                should_succeed: bool | None = None,
                message: str | None = None,
            ) -> m.Ldif.Acl | None:
                """Parse ACL content and unwrap the resulting model."""
                result = quirk.parse_quirk(content)
                if should_succeed is False:
                    if result.success:
                        msg = message or "Expected failure but parse succeeded"
                        raise AssertionError(msg)
                    return None
                if result.failure:
                    msg = (
                        message or f"Expected success but parse failed: {result.error}"
                    )
                    raise AssertionError(msg)
                value = result.value
                if expected_type is not None and not isinstance(value, expected_type):
                    raise AssertionError(
                        f"Expected {expected_type.__name__}, got {type(value).__name__}",
                    )
                return value

            @staticmethod
            def quirk_write_and_unwrap(
                quirk: p.Ldif.Tests.WriteAttributeQuirk
                | p.Ldif.Tests.WriteObjectClassQuirk
                | p.Ldif.Tests.WriteAclQuirk,
                data: m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass | m.Ldif.Acl,
                *,
                write_method: t.Ldif.Tests.WriteMethod = "write",
                must_contain: t.StrSequence | None = None,
                message: str | None = None,
            ) -> str:
                """Write content with a quirk and unwrap the serialized output."""
                if write_method == "_write_attribute":
                    if not isinstance(quirk, p.Ldif.Tests.WriteAttributeQuirk):
                        msg = "_write_attribute is not supported by this quirk"
                        raise AssertionError(
                            msg,
                        )
                    if not isinstance(data, m.Ldif.SchemaAttribute):
                        msg = "_write_attribute requires a SchemaAttribute"
                        raise AssertionError(
                            msg,
                        )
                    result = quirk._write_attribute(data)
                elif write_method == "_write_objectclass":
                    if not isinstance(quirk, p.Ldif.Tests.WriteObjectClassQuirk):
                        msg = "_write_objectclass is not supported by this quirk"
                        raise AssertionError(
                            msg,
                        )
                    if not isinstance(data, m.Ldif.SchemaObjectClass):
                        msg = "_write_objectclass requires a SchemaObjectClass"
                        raise AssertionError(
                            msg,
                        )
                    result = quirk._write_objectclass(data)
                elif write_method == "_write_acl":
                    if not isinstance(quirk, p.Ldif.Tests.WriteAclQuirk):
                        msg = "_write_acl is not supported by this quirk"
                        raise AssertionError(msg)
                    if not isinstance(data, m.Ldif.Acl):
                        msg = "_write_acl requires an ACL model"
                        raise AssertionError(msg)
                    result = quirk._write_acl(data)
                else:
                    msg = f"{write_method} is not supported by this quirk"
                    raise AssertionError(msg)
                if result.failure:
                    msg = message or f"Write failed: {result.error}"
                    raise AssertionError(msg)
                serialized = result.value
                if must_contain is not None:
                    for fragment in must_contain:
                        if fragment not in serialized:
                            raise AssertionError(
                                f"'{fragment}' not found in output: {serialized[:200]}...",
                            )
                return serialized

            @staticmethod
            def acl_write_and_unwrap(
                quirk: p.Ldif.Tests.WriteAclContentQuirk,
                data: m.Ldif.Acl,
                *,
                must_contain: t.StrSequence | None = None,
                message: str | None = None,
            ) -> str:
                """Write ACL content and unwrap the serialized output."""
                result = quirk.write(data)
                if result.failure:
                    msg = message or f"Write failed: {result.error}"
                    raise AssertionError(msg)
                serialized = result.value
                if must_contain is not None:
                    for fragment in must_contain:
                        if fragment not in serialized:
                            raise AssertionError(
                                f"'{fragment}' not found in output: {serialized[:200]}...",
                            )
                return serialized


u = TestsFlextLdifUtilities

__all__ = ["TestsFlextLdifUtilities", "u"]
