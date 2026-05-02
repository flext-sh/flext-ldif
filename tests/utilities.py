"""Test utilities facade with shared helper re-exports."""

from __future__ import annotations

import os
import uuid
from collections.abc import (
    MutableMapping,
)
from pathlib import Path
from typing import ClassVar

from flext_ldap import u
from flext_tests import FlextTestsFixturesDSLMixin, FlextTestsUtilities, tk

from tests.constants import c
from tests.models import m
from tests.protocols import p
from tests.typings import t


class TestsFlextLdifUtilities(FlextTestsUtilities, u):
    """Project test utility namespace extension."""

    class Tests(FlextTestsUtilities.Tests, FlextTestsFixturesDSLMixin):
        """Flat test utility namespace for flext-ldif."""

        Docker = tk
        LdapConnectionLike = p.Ldap.Ldap3Connection
        LdapEntryLike = p.Ldap.Ldap3Entry

        logger: ClassVar[p.Logger] = u.fetch_logger(__name__)
        _resolved_admin_credentials: ClassVar[list[tuple[str, str] | None]] = [
            None,
        ]
        _FIXTURES_ROOT: ClassVar[Path] = c.Tests.FIXTURES_DIR
        _FILE_EXTENSION: ClassVar[str] = ".ldif"
        _fixture_metadata_cache: ClassVar[
            MutableMapping[Path, m.Tests.FixtureMetadata]
        ] = {}

        @staticmethod
        def create_server_from_url(
            server_url: str,
            *,
            get_info: c.Ldap.Ldap3GetInfo = c.Ldap.Ldap3GetInfo.ALL,
        ) -> p.Ldap.Ldap3Server:
            """Create an LDAP server from a URL for test connectivity checks."""
            return u.Ldap.create_server_from_url(server_url, get_info=get_info)

        @staticmethod
        def create_bare_server(
            host: str,
            *,
            port: int = c.Tests.DOCKER_PORT,
            get_info: c.Ldap.Ldap3GetInfo = c.Ldap.Ldap3GetInfo.NO_INFO,
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
            attributes: t.MappingKV[str, t.StrSequence] | None = None,
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
            entry = m.Ldif.Entry.model_validate(
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
            if not isinstance(entry, m.Ldif.Entry):
                msg = "Expected create_real_entry() to build an Entry model"
                raise AssertionError(msg)
            return entry

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
        def parametrize_real_data() -> t.SequenceOf[m.Tests.LdifTestData]:
            """Generate parametrized test data for comprehensive coverage."""
            server_types = ("generic", *c.Tests.PARAMETRIZED_REAL_SERVERS)
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
                for server_type in server_types
            ]

        FileLock = FlextTestsUtilities.Tests.FileLock

        @classmethod
        def fixture_metadata(
            cls,
            server_type: t.Tests.FixtureServer,
            fixture_type: t.Tests.FixtureKind,
        ) -> m.Tests.FixtureMetadata:
            """Return metadata for one fixture file."""
            file_path = cls.path(server_type, fixture_type)
            if file_path in cls._fixture_metadata_cache:
                return cls._fixture_metadata_cache[file_path]
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

        @staticmethod
        def get_docker_control(worker_id: str = "master") -> tk:
            """Create Docker test infrastructure controller."""
            return tk.compose(
                compose_file=c.Tests.DOCKER_COMPOSE_FILE_REL,
                container_name=c.Tests.DOCKER_CONTAINER_NAME,
                service=c.Tests.DOCKER_SERVICE_NAME,
                host=c.LOCALHOST,
                port=c.Tests.DOCKER_PORT,
                startup_timeout=15,
                workspace_root=c.Tests.PROJECT_ROOT,
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
                        c.Tests.DOCKER_ADMIN_DN,
                        c.Tests.DOCKER_ADMIN_PASSWORD,
                    ),
                    (
                        c.Tests.DOCKER_LEGACY_ADMIN_DN,
                        c.Tests.DOCKER_LEGACY_ADMIN_PASSWORD,
                    ),
                ],
            )
            for candidate_dn, candidate_password in candidates:
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
                c.Tests.DOCKER_ADMIN_DN,
                c.Tests.DOCKER_ADMIN_PASSWORD,
            )
            cache[0] = fallback
            return fallback

        @staticmethod
        def assert_server_schema_parse_and_properties(
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
            result = (
                server.parse_objectclass(schema_def)
                if is_objectclass
                else server.parse_attribute(schema_def)
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
        def server_parse_and_unwrap(
            server: (p.Ldif.SchemaServer | p.Tests.ParseInputServer),
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
            if parse_method == "parse_attribute":
                if not isinstance(server, p.Ldif.SchemaServer):
                    msg = "parse_attribute requires a schema server"
                    raise AssertionError(msg)
                result = server.parse_attribute(content)
            elif parse_method == "parse_objectclass":
                if not isinstance(server, p.Ldif.SchemaServer):
                    msg = "parse_objectclass requires a schema server"
                    raise AssertionError(
                        msg,
                    )
                result = server.parse_objectclass(content)
            elif parse_method == "parse_input":
                if not isinstance(server, p.Ldif.SchemaServer):
                    msg = "parse_input is not supported by this server"
                    raise AssertionError(msg)
                result = server.parse_input(content)
            else:
                msg = f"{parse_method} is not supported by this server"
                raise AssertionError(msg)
            if should_succeed is False:
                if result.success:
                    msg = message or "Expected failure but parse succeeded"
                    raise AssertionError(msg)
                return None
            if result.failure:
                msg = message or f"Expected success but parse failed: {result.error}"
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
                    msg = message or "Expected failure but parse succeeded"
                    raise AssertionError(msg)
                return None
            if result.failure:
                msg = message or f"Expected success but parse failed: {result.error}"
                raise AssertionError(msg)
            value = result.value
            if not isinstance(value, m.Ldif.Acl):
                msg = f"Expected ACL parse result, got {type(value).__name__}"
                raise AssertionError(msg)
            if expected_type is not None and not isinstance(value, expected_type):
                raise AssertionError(
                    f"Expected {expected_type.__name__}, got {type(value).__name__}",
                )
            return value

        @staticmethod
        def server_write_and_unwrap(
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
            if write_method == "_write_attribute":
                if not isinstance(server, p.Tests.WriteAttributeServer):
                    msg = "_write_attribute is not supported by this server"
                    raise AssertionError(
                        msg,
                    )
                if not isinstance(data, m.Ldif.SchemaAttribute):
                    msg = "_write_attribute requires a SchemaAttribute"
                    raise AssertionError(
                        msg,
                    )
                result = server._write_attribute(data)
            elif write_method == "_write_objectclass":
                if not isinstance(server, p.Tests.WriteObjectClassServer):
                    msg = "_write_objectclass is not supported by this server"
                    raise AssertionError(
                        msg,
                    )
                if not isinstance(data, m.Ldif.SchemaObjectClass):
                    msg = "_write_objectclass requires a SchemaObjectClass"
                    raise AssertionError(
                        msg,
                    )
                result = server._write_objectclass(data)
            elif write_method == "_write_acl":
                if not isinstance(server, p.Tests.WriteAclServer):
                    msg = "_write_acl is not supported by this server"
                    raise AssertionError(msg)
                if not isinstance(data, m.Ldif.Acl):
                    msg = "_write_acl requires an ACL model"
                    raise AssertionError(msg)
                result = server._write_acl(data)
            else:
                msg = f"{write_method} is not supported by this server"
                raise AssertionError(msg)
            if result.failure:
                msg = message or f"Write failed: {result.error}"
                raise AssertionError(msg)
            serialized = result.value
            if not isinstance(serialized, str):
                msg = (
                    f"Expected serialized LDIF output, got {type(serialized).__name__}"
                )
                raise AssertionError(msg)
            if must_contain is not None:
                for fragment in must_contain:
                    if fragment not in serialized:
                        raise AssertionError(
                            f"'{fragment}' not found in output: {serialized[:200]}...",
                        )
            return serialized

        @staticmethod
        def acl_write_and_unwrap(
            server: p.Tests.WriteAclContentServer,
            data: m.Ldif.Acl,
            *,
            must_contain: t.StrSequence | None = None,
            message: str | None = None,
        ) -> str:
            """Write ACL content and unwrap the serialized output."""
            result = server.write(data)
            if result.failure:
                msg = message or f"Write failed: {result.error}"
                raise AssertionError(msg)
            serialized = result.value
            if not isinstance(serialized, str):
                msg = f"Expected serialized ACL output, got {type(serialized).__name__}"
                raise AssertionError(msg)
            if must_contain is not None:
                for fragment in must_contain:
                    if fragment not in serialized:
                        raise AssertionError(
                            f"'{fragment}' not found in output: {serialized[:200]}...",
                        )
            return serialized


u = TestsFlextLdifUtilities

__all__: list[str] = ["TestsFlextLdifUtilities", "u"]
