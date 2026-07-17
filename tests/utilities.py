"""Test utilities facade with shared helper re-exports."""

from __future__ import annotations

import os
import uuid
from pathlib import Path
from typing import TYPE_CHECKING, ClassVar, overload

from flext_ldap import FlextLdapUtilities, u
from flext_tests import FlextTestsUtilities, tk, tm
from flext_tests._utilities.fixtures_dsl import FlextTestsFixturesDSLMixin

from tests import c, m, p, t

if TYPE_CHECKING:
    from collections.abc import Callable, MutableMapping


class TestsFlextLdifUtilities(FlextTestsUtilities, u):
    """Project test utility namespace extension."""

    class Tests(FlextTestsFixturesDSLMixin, FlextTestsUtilities.Tests):
        """Flat test utility namespace for flext-ldif."""

        Docker = tk
        LdapConnectionLike = p.Ldap.Ldap3Connection
        LdapEntryLike = p.Ldap.Ldap3Entry

        logger: ClassVar[p.Logger] = FlextLdapUtilities.fetch_logger(__name__)
        _resolved_admin_credentials: ClassVar[list[tuple[str, str] | None]] = [None]
        _FIXTURES_ROOT: ClassVar[Path] = c.Tests.FIXTURES_DIR
        _FILE_EXTENSION: ClassVar[str] = ".ldif"
        _fixture_metadata_cache: ClassVar[
            MutableMapping[Path, m.Tests.FixtureMetadata]
        ] = {}
        FileLock = FlextTestsUtilities.Tests.FileLock

        @staticmethod
        def create_server_from_url(
            server_url: str,
            *,
            get_info: c.Ldap.Ldap3GetInfo = c.Ldap.Ldap3GetInfo.ALL,
        ) -> p.Ldap.Ldap3Server:
            """Create an LDAP server from a URL for test connectivity checks."""
            return FlextLdapUtilities.Ldap.create_server_from_url(
                server_url,
                get_info=get_info,
            )

        @classmethod
        def create_bare_server(
            cls,
            host: str,
            *,
            port: int = c.Tests.DOCKER_PORT,
            get_info: c.Ldap.Ldap3GetInfo = c.Ldap.Ldap3GetInfo.NO_INFO,
        ) -> p.Ldap.Ldap3Server:
            """Create a minimal LDAP server for connectivity checks."""
            return cls.create_server_from_url(
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
                return FlextLdapUtilities.Ldap.create_connection(
                    server,
                    user=user,
                    password=password,
                    auto_bind=auto_bind,
                )
            return FlextLdapUtilities.Ldap.create_connection(
                server,
                user=user,
                password=password,
                auto_bind=auto_bind,
                receive_timeout=receive_timeout,
            )

        @staticmethod
        def create_real_entry(
            dn: str | None = None,
            attributes: t.MappingKV[str, t.StrSequence] | None = None,
            server_type: str = "generic",
        ) -> m.Ldif.Entry:
            """Create a real Entry model with valid data."""
            entry_id = uuid.uuid4().hex[:8]
            payload_attrs = attributes or {
                "cn": [f"test-{entry_id}"],
                "sn": ["Test"],
                "mail": [f"test-{entry_id}@example.com"],
                "objectClass": ["person", "organizationalPerson", "inetOrgPerson"],
            }
            entry: m.Ldif.Entry = m.Ldif.Entry.model_validate({
                "dn": {"value": dn or f"cn=test-{entry_id},ou=users,dc=example,dc=com"},
                "attributes": {
                    "attributes": {k: list(v) for k, v in payload_attrs.items()},
                },
                "server_type": server_type,
            })
            return entry

        @staticmethod
        def create_real_ldif_content(
            entries_count: int = 3,
            *,
            include_schema: bool = False,
        ) -> str:
            """Create real LDIF content for testing."""
            blocks: list[str] = []
            if include_schema:
                blocks.append(
                    "dn: cn=schema\n"
                    "objectClass: top\n"
                    "objectClass: ldapSubentry\n"
                    "objectClass: subschema\n"
                    "\n"
                    "attributeTypes: ( 2.5.4.3 NAME 'cn' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )\n",
                )
            for index in range(entries_count):
                entry_id = uuid.uuid4().hex[:8]
                blocks.append(
                    f"dn: cn=user-{entry_id},ou=users,dc=example,dc=com\n"
                    "objectClass: person\n"
                    "objectClass: organizationalPerson\n"
                    "objectClass: inetOrgPerson\n"
                    f"cn: User {entry_id}\n"
                    f"sn: Test{index}\n"
                    f"mail: user{entry_id}@example.com\n",
                )
            return "\n".join(blocks)

        @staticmethod
        def parametrize_real_data() -> t.SequenceOf[m.Tests.LdifTestData]:
            """Generate parametrized test data for comprehensive coverage."""
            return [
                m.Tests.LdifTestData(
                    id=f"entry_{server_type}",
                    server_type=server_type,
                    dn=f"cn=test-{server_type},ou=users,dc=example,dc=com",
                    attributes={
                        "cn": [f"test-{server_type}"],
                        "objectClass": ["person", "organizationalPerson"],
                    },
                )
                for server_type in ("generic", *c.Tests.PARAMETRIZED_REAL_SERVERS)
            ]

        @classmethod
        def fixture_metadata(
            cls,
            server_type: t.Tests.FixtureServer,
            fixture_type: t.Tests.FixtureKind,
        ) -> m.Tests.FixtureMetadata:
            """Return metadata for one fixture file (cached per file path)."""
            file_path = cls.path(server_type, fixture_type)
            cached = cls._fixture_metadata_cache.get(file_path)
            if cached is not None:
                return cached
            content = cls.load(server_type, fixture_type)
            lines = content.splitlines()
            metadata = m.Tests.FixtureMetadata(
                server_type=server_type,
                fixture_type=fixture_type,
                file_path=file_path,
                line_count=len(lines),
                entry_count=sum(1 for line in lines if line.strip().startswith("dn:")),
                size_bytes=file_path.stat().st_size,
            )
            cls._fixture_metadata_cache[file_path] = metadata
            return metadata

        @classmethod
        def get_docker_control(cls, worker_id: str = "master") -> tk:
            """Create Docker test infrastructure controller."""
            compose_file = Path(
                str(
                    c.Tests.SHARED_CONTAINERS[c.Tests.DOCKER_CONTAINER_NAME][
                        "compose_file"
                    ],
                ),
            )
            workspace_root = next(
                (
                    candidate
                    for candidate in (
                        c.Tests.PROJECT_ROOT,
                        *c.Tests.PROJECT_ROOT.parents,
                    )
                    if (candidate / compose_file).is_file()
                ),
                c.Tests.PROJECT_ROOT,
            )
            return tk.shared(
                c.Tests.DOCKER_CONTAINER_NAME,
                workspace_root=workspace_root,
                worker_id=worker_id,
            )

        @classmethod
        def get_admin_credentials(cls) -> tuple[str, str]:
            """Resolve LDAP admin credentials, preferring a working pair."""
            cache = cls._resolved_admin_credentials
            cached = cache[0]
            if cached is not None:
                return cached
            env_dn = os.getenv("FLEXT_LDAP_BIND_DN")
            env_password = os.getenv("FLEXT_LDAP_BIND_PASSWORD")
            candidates: list[tuple[str, str]] = [
                *([(env_dn, env_password)] if env_dn and env_password else []),
                (c.Tests.DOCKER_ADMIN_DN, c.Tests.DOCKER_ADMIN_PASSWORD),
                (c.Tests.DOCKER_LEGACY_ADMIN_DN, c.Tests.DOCKER_LEGACY_ADMIN_PASSWORD),
            ]
            for candidate_dn, candidate_password in candidates:
                credentials = cls._probe_admin_credentials(
                    candidate_dn,
                    candidate_password,
                )
                if credentials is None:
                    continue
                cache[0] = credentials
                return credentials
            default_credentials = (
                c.Tests.DOCKER_ADMIN_DN,
                c.Tests.DOCKER_ADMIN_PASSWORD,
            )
            cache[0] = default_credentials
            return default_credentials

        @classmethod
        def _probe_admin_credentials(
            cls,
            candidate_dn: str,
            candidate_password: str,
        ) -> tuple[str, str] | None:
            """Return candidate credentials when LDAP bind succeeds."""
            try:
                server = cls.create_bare_server(
                    "localhost",
                    port=c.Tests.DOCKER_PORT,
                    get_info=c.Ldap.Ldap3GetInfo.NO_INFO,
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
                    return (candidate_dn, candidate_password)
                return None
            except (
                ConnectionError,
                OSError,
                ValueError,
                t.Ldap.LDAPException,
            ):
                return None

        @staticmethod
        def _assert_field_eq(
            value: object,
            field: str,
            expected: object,
            label: str,
        ) -> None:
            """Assert ``getattr(value, field) == expected`` with consistent diagnostic."""
            if expected is None:
                return
            actual = getattr(value, field, None)
            if isinstance(expected, list) and actual is not None:
                if list(actual) != list(expected):
                    raise AssertionError(f"Expected {label} {expected}, got {actual}")
                return
            if actual != expected:
                raise AssertionError(f"Expected {label} '{expected}', got {actual}")

        @classmethod
        def assert_server_schema_parse_and_properties(
            cls,
            server: p.Ldif.SchemaServer,
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
                    c.Tests.SCHEMA_STRUCTURAL,
                    c.Tests.SCHEMA_AUXILIARY,
                    c.Tests.SCHEMA_ABSTRACT,
                )
            )
            value_raw = tm.ok(
                server.parse_objectclass(schema_def)
                if is_objectclass
                else server.parse_attribute(schema_def),
            )
            value: m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass
            if is_objectclass:
                value = m.Ldif.SchemaObjectClass.model_validate(value_raw)
            else:
                value = m.Ldif.SchemaAttribute.model_validate(value_raw)
            common_checks: tuple[tuple[str, object, str], ...] = (
                ("oid", expected_oid, "OID"),
                ("name", expected_name, "NAME"),
                ("desc", expected_desc, "DESC"),
            )
            for field, expected, label in common_checks:
                cls._assert_field_eq(value, field, expected, label)
            if isinstance(value, m.Ldif.SchemaAttribute):
                attr_checks: tuple[tuple[str, object, str], ...] = (
                    ("syntax", expected_syntax, "SYNTAX"),
                    ("single_value", expected_single_value, "SINGLE-VALUE"),
                    ("length", expected_length, "length"),
                )
                for field, expected, label in attr_checks:
                    cls._assert_field_eq(value, field, expected, label)
                return value
            oc_checks: tuple[tuple[str, object, str], ...] = (
                ("kind", expected_kind, "KIND"),
                ("sup", expected_sup, "SUP"),
                (
                    "must",
                    list(expected_must) if expected_must is not None else None,
                    "MUST",
                ),
                (
                    "may",
                    list(expected_may) if expected_may is not None else None,
                    "MAY",
                ),
            )
            for field, expected, label in oc_checks:
                cls._assert_field_eq(value, field, expected, label)
            return value

        _PARSE_DISPATCH: ClassVar[t.MappingKV[t.Tests.ParseMethod, str]] = {
            "parse_attribute": "parse_attribute",
            "parse_objectclass": "parse_objectclass",
            "parse_input": "parse_input",
        }

        @overload
        @classmethod
        def server_parse_and_unwrap[
            SchemaNodeT: (m.Ldif.SchemaAttribute, m.Ldif.SchemaObjectClass, m.Ldif.Acl)
        ](
            cls,
            server: p.Ldif.SchemaServer | p.Tests.ParseInputServer,
            content: str,
            *,
            parse_method: t.Tests.ParseMethod = ...,
            expected_type: type[SchemaNodeT],
            should_succeed: bool | None = ...,
            message: str | None = ...,
        ) -> SchemaNodeT | None: ...
        @overload
        @classmethod
        def server_parse_and_unwrap(
            cls,
            server: p.Ldif.SchemaServer | p.Tests.ParseInputServer,
            content: str,
            *,
            parse_method: t.Tests.ParseMethod = ...,
            expected_type: None = ...,
            should_succeed: bool | None = ...,
            message: str | None = ...,
        ) -> m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass | m.Ldif.Acl | None: ...
        @classmethod
        def server_parse_and_unwrap(
            cls,
            server: p.Ldif.SchemaServer | p.Tests.ParseInputServer,
            content: str,
            *,
            parse_method: t.Tests.ParseMethod = "parse_server",
            expected_type: (
                type[m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass | m.Ldif.Acl]
                | None
            ) = None,
            should_succeed: bool | None = None,
            message: str | None = None,
        ) -> m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass | m.Ldif.Acl | None:
            """Parse content with a server and unwrap the typed result."""
            method_name = cls._PARSE_DISPATCH.get(parse_method)
            if method_name is None or not isinstance(server, p.Ldif.SchemaServer):
                msg = f"{parse_method} is not supported by this server"
                raise AssertionError(msg)
            method: Callable[[str], p.Result[object]] = getattr(server, method_name)
            result = method(content)
            if should_succeed is False:
                if result.success:
                    raise AssertionError(
                        message or "Expected failure but parse succeeded",
                    )
                return None
            if result.failure:
                raise AssertionError(
                    message or f"Expected success but parse failed: {result.error}",
                )
            value = result.value
            if expected_type is not None and not isinstance(value, expected_type):
                raise AssertionError(
                    f"Expected {expected_type.__name__}, got {type(value).__name__}",
                )
            if isinstance(
                value,
                (m.Ldif.SchemaAttribute, m.Ldif.SchemaObjectClass, m.Ldif.Acl),
            ):
                return value
            return None

        @staticmethod
        def acl_parse_and_unwrap(
            server: p.Tests.ParseAclServer,
            content: str,
            *,
            expected_type: type[m.Ldif.Acl] | None = None,
            should_succeed: bool | None = None,
            message: str | None = None,
        ) -> m.Ldif.Acl | None:
            """Parse ACL content and unwrap the resulting model."""
            result = server.parse_server(content)
            if should_succeed is False:
                if result.success:
                    raise AssertionError(
                        message or "Expected failure but parse succeeded",
                    )
                return None
            if result.failure:
                raise AssertionError(
                    message or f"Expected success but parse failed: {result.error}",
                )
            value: m.Ldif.Acl = result.unwrap()
            if expected_type is not None and not isinstance(value, expected_type):
                raise AssertionError(
                    f"Expected {expected_type.__name__}, got {type(value).__name__}",
                )
            return value

        @staticmethod
        def _assert_must_contain(serialized: str, must_contain: t.StrSequence) -> None:
            """Assert every fragment in ``must_contain`` appears in ``serialized``."""
            for fragment in must_contain:
                if fragment not in serialized:
                    raise AssertionError(
                        f"'{fragment}' not found in output: {serialized[:200]}...",
                    )

        @classmethod
        def server_write_and_unwrap(
            cls,
            server: p.Tests.WriteAttributeServer
            | p.Tests.WriteObjectClassServer
            | p.Tests.WriteAclServer,
            data: m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass | m.Ldif.Acl,
            *,
            write_method: t.Tests.WriteMethod = "write",
            must_contain: t.StrSequence | None = None,
            message: str | None = None,
        ) -> str:
            """Write content with a server and unwrap the serialized output."""
            dispatch: t.MappingKV[
                t.Tests.WriteMethod,
                tuple[type, type[m.BaseModel]],
            ] = {
                "_write_attribute": (
                    p.Tests.WriteAttributeServer,
                    m.Ldif.SchemaAttribute,
                ),
                "_write_objectclass": (
                    p.Tests.WriteObjectClassServer,
                    m.Ldif.SchemaObjectClass,
                ),
                "_write_acl": (p.Tests.WriteAclServer, m.Ldif.Acl),
            }
            entry = dispatch.get(write_method)
            if entry is None:
                raise AssertionError(f"{write_method} is not supported by this server")
            server_proto, data_cls = entry
            if not isinstance(server, server_proto):
                raise AssertionError(f"{write_method} is not supported by this server")
            if not isinstance(data, data_cls):
                raise AssertionError(f"{write_method} requires a {data_cls.__name__}")
            method: Callable[[m.BaseModel], p.Result[str]] = getattr(
                server,
                write_method,
            )
            result = method(data)
            if result.failure:
                raise AssertionError(message or f"Write failed: {result.error}")
            serialized: str = result.unwrap()
            if must_contain is not None:
                cls._assert_must_contain(serialized, must_contain)
            return serialized

        @classmethod
        def acl_write_and_unwrap(
            cls,
            server: p.Tests.WriteAclContentServer,
            data: m.Ldif.Acl,
            *,
            must_contain: t.StrSequence | None = None,
            message: str | None = None,
        ) -> str:
            """Write ACL content and unwrap the serialized output."""
            result = server.write(data)
            if result.failure:
                raise AssertionError(message or f"Write failed: {result.error}")
            serialized: str = result.unwrap()
            if must_contain is not None:
                cls._assert_must_contain(serialized, must_contain)
            return serialized


u = TestsFlextLdifUtilities

__all__: list[str] = ["TestsFlextLdifUtilities", "u"]
