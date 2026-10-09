"""Test utilities facade with shared helper re-exports.

The focused helper mixins live in ``tests._utilities_ldap``,
``tests._utilities_entries``, and ``tests._utilities_schema``; this module is
the stable import surface and re-exports the composed namespace.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import importlib
import os
import uuid
from typing import TYPE_CHECKING, ClassVar, Final

import pytest
from flext_tests import FlextTestsFixturesDSLMixin, FlextTestsUtilities, tk, tm

from flext_ldif import FlextLdifUtilities
from tests import c, m, t
from tests._utilities_schema import (
    _PARSE_DISPATCH,
    SchemaExpectations,
    _assert_field_eq,
    _assert_must_contain,
)

if TYPE_CHECKING:
    from collections.abc import Callable, MutableMapping
    from pathlib import Path
    from types import ModuleType

    from tests import p


class TestsFlextLdifUtilities(FlextTestsUtilities, FlextLdifUtilities):
    """Project test utility namespace extension."""

    class TestsSchemaAclAssertionsMixin:
        """Parse/write assertion helpers for schema and ACL servers."""

        SchemaExpectations: ClassVar[type[SchemaExpectations]] = SchemaExpectations

        @staticmethod
        def _schema_definition_is_objectclass(schema_def: str) -> bool:
            """Whether the definition text declares an objectClass kind.

            Returns:
                True when the definition text declares an objectClass kind.
            """
            return any(
                kind in schema_def
                for kind in (
                    c.Tests.SCHEMA_STRUCTURAL,
                    c.Tests.SCHEMA_AUXILIARY,
                    c.Tests.SCHEMA_ABSTRACT,
                )
            )

        @staticmethod
        def _parse_schema_definition(
            server: p.Ldif.SchemaServer,
            schema_def: str,
        ) -> m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass:
            """Parse one schema definition through the kind-matching server method.

            Returns:
                The resulting ``m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass``.
            """
            is_objectclass = (
                TestsFlextLdifUtilities.TestsSchemaAclAssertionsMixin._schema_definition_is_objectclass
            )
            if is_objectclass(schema_def):
                value_raw = tm.ok(server.parse_objectclass(schema_def))
                value: m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass = (
                    m.Ldif.SchemaObjectClass.model_validate(value_raw)
                )
                return value
            attribute_raw = tm.ok(server.parse_attribute(schema_def))
            attribute: m.Ldif.SchemaAttribute = m.Ldif.SchemaAttribute.model_validate(
                attribute_raw,
            )
            return attribute

        @staticmethod
        def _assert_common_expectations(
            value: m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass,
            expectations: SchemaExpectations,
        ) -> None:
            """Assert the OID/NAME/DESC fields shared by both schema kinds."""
            common_checks: tuple[tuple[str, object, str], ...] = (
                ("oid", expectations.oid, "OID"),
                ("name", expectations.name, "NAME"),
                ("desc", expectations.desc, "DESC"),
            )
            for field, expected, label in common_checks:
                _assert_field_eq(value, field, expected, label)

        @staticmethod
        def _assert_attribute_expectations(
            value: m.Ldif.SchemaAttribute,
            expectations: SchemaExpectations,
        ) -> None:
            """Assert the attribute-only SYNTAX/SINGLE-VALUE/length fields."""
            attr_checks: tuple[tuple[str, object, str], ...] = (
                ("syntax", expectations.syntax, "SYNTAX"),
                ("single_value", expectations.single_value, "SINGLE-VALUE"),
                ("length", expectations.length, "length"),
            )
            for field, expected, label in attr_checks:
                _assert_field_eq(value, field, expected, label)

        @staticmethod
        def _assert_objectclass_expectations(
            value: m.Ldif.SchemaObjectClass,
            expectations: SchemaExpectations,
        ) -> None:
            """Assert the objectClass-only KIND/SUP/MUST/MAY fields."""
            oc_checks: tuple[tuple[str, object, str], ...] = (
                ("kind", expectations.kind, "KIND"),
                ("sup", expectations.sup, "SUP"),
                (
                    "must",
                    list(expectations.must) if expectations.must is not None else None,
                    "MUST",
                ),
                (
                    "may",
                    list(expectations.may) if expectations.may is not None else None,
                    "MAY",
                ),
            )
            for field, expected, label in oc_checks:
                _assert_field_eq(value, field, expected, label)

        @classmethod
        def assert_server_schema_parse_and_properties(
            cls,
            server: p.Ldif.SchemaServer,
            schema_def: str,
            *,
            expectations: SchemaExpectations,
        ) -> m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass:
            """Parse schema content and assert the expected properties.

            Returns:
                The resulting ``m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass``.
            """
            value = cls._parse_schema_definition(server, schema_def)
            cls._assert_common_expectations(value, expectations)
            if isinstance(value, m.Ldif.SchemaAttribute):
                cls._assert_attribute_expectations(value, expectations)
            else:
                cls._assert_objectclass_expectations(value, expectations)
            return value

        @staticmethod
        def server_parse_and_unwrap[
            SchemaNodeT: (m.Ldif.SchemaAttribute, m.Ldif.SchemaObjectClass, m.Ldif.Acl),
        ](
            server: p.Ldif.SchemaServer | p.Tests.ParseInputServer,
            content: str,
            parse_method: t.Tests.ParseMethod = "parse_server",
            *,
            expected_type: type[SchemaNodeT],
            should_succeed: bool | None = None,
        ) -> SchemaNodeT | None:
            """Parse content with a server and unwrap the typed result.

            Returns:
                The resulting ``SchemaNodeT | None``.

            Raises:
                AssertionError: If ``method_name is None or not isinstance(server,
                    p.Ldif.SchemaServer)``; or if ``result.failure``; or if Expected; or
                    if ``result.success``.

            Raises:
                TypeError: If ``method_name is None or not isinstance(server,
                    p.Ldif.SchemaServer)``; or if the parsed value does not match
                    ``expected_type``.
                AssertionError: If ``result.failure``; or if Expected; or
                    if ``result.success``.
            """
            method_name = _PARSE_DISPATCH.get(parse_method)
            if method_name is None or not isinstance(server, p.Ldif.SchemaServer):
                msg = f"{parse_method} is not supported by this server"
                raise AssertionError(msg)
            method: Callable[
                [str],
                p.Result[
                    m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass | m.Ldif.Acl
                ],
            ] = getattr(server, method_name)
            result = method(content)
            if should_succeed is False:
                if result.success:
                    msg_0 = "Expected failure but parse succeeded"
                    raise AssertionError(msg_0)
                return None
            if result.failure:
                msg_0 = f"Expected success but parse failed: {result.error}"
                raise AssertionError(
                    msg_0,
                )
            value = result.value
            if not isinstance(value, expected_type):
                msg_0 = f"Expected {expected_type.__name__}, got {type(value).__name__}"
                raise TypeError(msg_0)
            # `method` is typed to return exactly these three models, so the
            # isinstance narrowing above is total and no fallthrough exists.
            return value

        @staticmethod
        def acl_parse_and_unwrap(
            server: p.Tests.ParseAclServer,
            content: str,
            expected_type: type[m.Ldif.Acl] | None = None,
            *,
            should_succeed: bool | None = None,
            message: str | None = None,
        ) -> m.Ldif.Acl | None:
            """Parse ACL content and unwrap the resulting model.

            Returns:
                The resulting ``m.Ldif.Acl | None``.

            Raises:
                AssertionError: If ``result.failure``; or if Expected; or if
                    ``result.success``.
            """
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
                msg = f"Expected {expected_type.__name__}, got {type(value).__name__}"
                raise AssertionError(msg)
            return value

        @staticmethod
        def server_write_and_unwrap(
            server: p.Tests.WriteAttributeServer
            | p.Tests.WriteObjectClassServer
            | p.Tests.WriteAclServer,
            data: m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass | m.Ldif.Acl,
            write_method: t.Tests.WriteMethod = "write",
            must_contain: t.StrSequence | None = None,
            message: str | None = None,
        ) -> str:
            """Write content with a server and unwrap the serialized output.

            Returns:
                The resulting ``str``.

            Raises:
                AssertionError: If ``entry is None``; or if ``result.failure``.
                TypeError: If ``not isinstance(server, server_proto)``; or if ``not
                    isinstance(data, data_cls)``.
            """
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
                msg = f"{write_method} is not supported by this server"
                raise AssertionError(msg)
            # Why: widen from the dict's per-key literal tuple type so the
            # isinstance guards below stay a real runtime check (write_method
            # is caller-supplied and can mismatch server/data at runtime)
            # rather than a statically-tautological one (pyright
            # reportUnnecessaryIsInstance).
            server_proto: type
            data_cls: type
            server_proto, data_cls = entry
            if not isinstance(server, server_proto):
                msg = f"{write_method} is not supported by this server"
                raise TypeError(msg)
            if not isinstance(data, data_cls):
                msg = f"{write_method} requires a {data_cls.__name__}"
                raise TypeError(msg)
            method: Callable[[m.BaseModel], p.Result[str]] = getattr(
                server,
                write_method,
            )
            result = method(data)
            if result.failure:
                raise AssertionError(message or f"Write failed: {result.error}")
            serialized: str = result.unwrap()
            if must_contain is not None:
                _assert_must_contain(serialized, must_contain)
            return serialized

        @staticmethod
        def acl_write_and_unwrap(
            server: p.Tests.WriteAclContentServer,
            data: m.Ldif.Acl,
            must_contain: t.StrSequence | None = None,
            message: str | None = None,
        ) -> str:
            """Write ACL content and unwrap the serialized output.

            Returns:
                The resulting ``str``.

            Raises:
                AssertionError: If ``result.failure``.
            """
            result = server.write(data)
            if result.failure:
                raise AssertionError(message or f"Write failed: {result.error}")
            serialized: str = result.unwrap()
            if must_contain is not None:
                _assert_must_contain(serialized, must_contain)
            return serialized

    class TestsLdapClientMixin:
        """Helpers that drive the optional real-directory LDAP client.

        The real-directory tests drive a live LDAP server through the FLEXT LDAP
        client, but that client is built ON TOP of flext-ldif: declaring it here
        would invert the layer and close a dependency cycle, so it can never belong
        to this project's dependency set. It is therefore resolved dynamically and
        every test that needs it skips explicitly when it is absent — which is the
        case for any standalone checkout, CI included.
        """

        _LDAP_CLIENT_MODULE: Final[str] = "flext_ldap"

        _LDAP_ENTRY_ADAPTER_MODULE: Final[str] = "flext_ldap.adapters.entry"

        _LDAP_CLIENT_MISSING_REASON: Final[str] = (
            f"LDAP client {_LDAP_CLIENT_MODULE!r} is unavailable: it depends on"
            " flext-ldif and cannot be a dependency of it, so real-directory tests"
            " only run in a workspace checkout that provides the client."
        )

        _resolved_admin_credentials: ClassVar[list[tuple[str, str] | None]] = [None]

        @staticmethod
        def _import_optional(module_name: str) -> ModuleType | None:
            """Import an optional module, returning None when it is not installed.

            Returns:
                The resulting ``ModuleType | None``.
            """
            return importlib.import_module(module_name)

        @classmethod
        def ldap_client_available(cls) -> bool:
            """Whether the optional LDAP client is importable.

            Returns:
                The resulting ``bool``.
            """
            return cls._import_optional(cls._LDAP_CLIENT_MODULE) is not None

        @classmethod
        def require_ldap_client(cls) -> ModuleType:
            """Return the LDAP client module, skipping when it is unavailable."""
            module = cls._import_optional(cls._LDAP_CLIENT_MODULE)
            if module is None:
                pytest.skip(cls._LDAP_CLIENT_MISSING_REASON)
            return module

        @classmethod
        def create_ldap_entry_adapter(cls) -> p.Ldap.Ldap3EntryAdapter:
            """Return an ldap3-to-LDIF entry adapter, skipping when unavailable."""
            module = cls._import_optional(cls._LDAP_ENTRY_ADAPTER_MODULE)
            if module is None:
                pytest.skip(cls._LDAP_CLIENT_MISSING_REASON)
            adapter: p.Ldap.Ldap3EntryAdapter = module.FlextLdapEntryAdapter()
            return adapter

        @classmethod
        def ldap_connectivity_errors(cls) -> tuple[type[BaseException], ...]:
            """Exception types signalling that the LDAP server is unreachable.

            Returns:
                The resulting ``tuple[type[BaseException], ...]``.
            """
            transport: tuple[type[BaseException], ...] = (
                ConnectionError,
                TimeoutError,
                OSError,
            )
            module = cls._import_optional(cls._LDAP_CLIENT_MODULE)
            if module is None:
                return transport
            protocol_error: type[BaseException] = module.t.Ldap.LDAPException
            return (protocol_error, *transport)

        @classmethod
        def create_server_from_url(
            cls,
            server_url: str,
            *,
            get_info: c.Ldap.Ldap3GetInfo = c.Ldap.Ldap3GetInfo.ALL,
        ) -> p.Ldap.Ldap3Server:
            """Create an LDAP server from a URL for test connectivity checks.

            Returns:
                The resulting ``p.Ldap.Ldap3Server``.
            """
            client = cls.require_ldap_client()
            server: p.Ldap.Ldap3Server = (
                client.FlextLdapUtilities.Ldap.create_server_from_url(
                    server_url,
                    get_info=get_info,
                )
            )
            return server

        @classmethod
        def create_bare_server(
            cls,
            host: str,
            *,
            port: int = c.Tests.DOCKER_PORT,
            get_info: c.Ldap.Ldap3GetInfo = c.Ldap.Ldap3GetInfo.NO_INFO,
        ) -> p.Ldap.Ldap3Server:
            """Create a minimal LDAP server for connectivity checks.

            Returns:
                The resulting ``p.Ldap.Ldap3Server``.
            """
            return cls.create_server_from_url(
                f"ldap://{host}:{port}",
                get_info=get_info,
            )

        @staticmethod
        def create_connection(
            server: p.Ldap.Ldap3Server,
            user: str,
            password: str,
            *,
            auto_bind: bool = True,
            receive_timeout: int | None = None,
        ) -> p.Ldap.Ldap3Connection:
            """Create an LDAP connection for test workflows.

            Returns:
                The resulting ``p.Ldap.Ldap3Connection``.
            """
            client = TestsFlextLdifUtilities.TestsLdapClientMixin.require_ldap_client()
            create = client.FlextLdapUtilities.Ldap.create_connection
            if receive_timeout is None:
                connection: p.Ldap.Ldap3Connection = create(
                    server,
                    user=user,
                    password=password,
                    auto_bind=auto_bind,
                )
                return connection
            timed_connection: p.Ldap.Ldap3Connection = create(
                server,
                user=user,
                password=password,
                auto_bind=auto_bind,
                receive_timeout=receive_timeout,
            )
            return timed_connection

        @classmethod
        def _probe_admin_credentials(
            cls,
            candidate_dn: str,
            candidate_password: str,
        ) -> tuple[str, str] | None:
            """Return candidate credentials when LDAP bind succeeds."""
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
            bound: bool = connection.bound
            if bound:
                connection.unbind()
            if bound:
                return (candidate_dn, candidate_password)
            return None

        @classmethod
        def get_admin_credentials(cls) -> tuple[str, str]:
            """Resolve LDAP admin credentials, preferring a working pair.

            Returns:
                The resulting ``tuple[str, str]``.
            """
            cache = cls._resolved_admin_credentials
            cached = cache[0]
            if cached is not None:
                return cached
            env_dn = os.getenv("FLEXT_LDAP_BIND_DN")
            env_password = os.getenv("FLEXT_LDAP_BIND_PASSWORD")
            candidates: list[tuple[str, str]] = [
                *([(env_dn, env_password)] if env_dn and env_password else []),
                (c.Tests.DOCKER_ADMIN_DN, c.Tests.DOCKER_ADMIN_CREDENTIAL),
                (
                    c.Tests.DOCKER_LEGACY_ADMIN_DN,
                    c.Tests.DOCKER_LEGACY_ADMIN_CREDENTIAL,
                ),
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
                c.Tests.DOCKER_ADMIN_CREDENTIAL,
            )
            cache[0] = default_credentials
            return default_credentials

        @staticmethod
        def get_docker_control() -> tk:
            """Create Docker test infrastructure controller.

            Returns:
                The resulting ``tk``.
            """
            compose_file = Path(
                str(
                    c.Tests.SHARED_CONTAINERS[c.Tests.DOCKER_CONTAINER_NAME][
                        "compose_file"
                    ],
                ),
            )
            repository_root = next(
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
                repository_root=repository_root,
            )

    class TestsLdifEntryBuildersMixin(FlextTestsFixturesDSLMixin):
        """Builders for real entry models, LDIF content, and fixture metadata."""

        _FIXTURES_ROOT: ClassVar[Path] = c.Tests.FIXTURES_DIR
        _FILE_EXTENSION: ClassVar[str] = ".ldif"
        _fixture_metadata_cache: ClassVar[
            MutableMapping[Path, m.Tests.FixtureMetadata]
        ] = {}

        @staticmethod
        def create_real_entry(
            dn: str | None = None,
            attributes: t.MappingKV[str, t.StrSequence] | None = None,
            server_type: str = "generic",
        ) -> m.Ldif.Entry:
            """Create a real Entry model with valid data.

            Returns:
                The resulting ``m.Ldif.Entry``.
            """
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

        @classmethod
        def orclaci_base_dn_entry(cls, dn: str = "cn=users,dc=ctbc") -> m.Ldif.Entry:
            """Build a real LDIF entry with an out-of-scope ``orclaci`` OID line.

            The OID line doubles as a base-DN filter test payload.

            Returns:
                The resulting ``m.Ldif.Entry``.
            """
            return cls.create_real_entry(
                dn=dn,
                attributes={
                    "objectClass": ["top"],
                    "orclaci": [
                        (
                            'access to entry by group="cn=x,dc=other" (browse) '
                            'by group="cn=a,dc=ctbc" (browse)'
                        ),
                    ],
                },
            )

        @staticmethod
        def create_real_ldif_content(
            entries_count: int = 3,
            *,
            include_schema: bool = False,
        ) -> str:
            """Create real LDIF content for testing.

            Returns:
                The resulting ``str``.
            """
            blocks: list[str] = []
            if include_schema:
                blocks.append(
                    "dn: cn=schema\n"
                    "objectClass: top\n"
                    "objectClass: ldapSubentry\n"
                    "objectClass: subschema\n"
                    "\n"
                    "attributeTypes: ( 2.5.4.3 NAME 'cn' SYNTAX "
                    "1.3.6.1.4.1.1466.115.121.1.15 )\n",
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
            """Generate parametrized test data for comprehensive coverage.

            Returns:
                The resulting ``t.SequenceOf[m.Tests.LdifTestData]``.
            """
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

    class Tests(
        TestsLdapClientMixin,
        TestsLdifEntryBuildersMixin,
        TestsSchemaAclAssertionsMixin,
        FlextTestsUtilities.Tests,
    ):
        """Flat test utility namespace for flext-ldif."""

        logger: ClassVar[p.Logger] = FlextLdifUtilities.fetch_logger(__name__)


u = TestsFlextLdifUtilities

__all__: list[str] = ["SchemaExpectations", "TestsFlextLdifUtilities", "u"]
