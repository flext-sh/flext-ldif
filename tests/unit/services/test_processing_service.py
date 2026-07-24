"""Behavioral tests for public LDIF processing service APIs."""

from __future__ import annotations

from typing import TYPE_CHECKING, Literal

import pytest

from flext_ldif.services.pipeline import FlextLdifProcessingPipeline
from flext_tests import tm
from tests import TestsFlextLdifUtilities as u, c, m

if TYPE_CHECKING:
    from tests import p, t


class TestsFlextLdifProcessingService:
    """Cover batch/parallel processing through the public facade only."""

    @staticmethod
    def _entry(dn: str) -> m.Ldif.Entry:
        return u.Tests.create_real_entry(
            dn=dn, attributes=c.Tests.PROCESSING_ATTRS, server_type=c.Tests.RFC
        )

    @pytest.mark.parametrize(
        ("processor_name", "parallel", "batch_size", "max_workers"),
        list(c.Tests.PROCESSING_OPTIONS_CASES.values()),
        ids=list(c.Tests.PROCESSING_OPTIONS_CASES.keys()),
    )
    def test_process_entries_returns_results_for_configured_modes(
        self,
        api: p.Ldif.LdifClient,
        processor_name: Literal["transform", "validate"],
        *,
        parallel: bool,
        batch_size: int,
        max_workers: int,
    ) -> None:
        entries = [self._entry(dn) for dn in c.Tests.PROCESSING_VALID_DNS]
        options = m.Ldif.ProcessEntriesOptions(
            processor_name=processor_name,
            parallel=parallel,
            batch_size=batch_size,
            max_workers=max_workers,
        )

        result = api.process_entries(entries, options=options)
        processed: t.MutableSequenceOf[m.Ldif.ProcessingResult] = (
            u.Tests.assert_success(result)
        )
        tm.that(len(processed), eq=len(entries))
        processed_dns = {item.dn for item in processed}
        tm.that(processed_dns == set(c.Tests.PROCESSING_VALID_DNS), eq=True)

    def test_process_entries_supports_kwargs_option_payload(
        self, api: p.Ldif.LdifClient
    ) -> None:
        entries = [self._entry(c.Tests.PROCESSING_VALID_DNS[0])]

        result = api.process_entries(
            entries,
            processor_name="transform",
            parallel=False,
            batch_size=1,
            max_workers=1,
        )
        processed: t.MutableSequenceOf[m.Ldif.ProcessingResult] = (
            u.Tests.assert_success(result)
        )
        tm.that(len(processed), eq=1)
        tm.that(processed[0].dn, eq=c.Tests.PROCESSING_VALID_DNS[0])

    def test_process_entries_batch_returns_failure_for_none_attributes(
        self, api: p.Ldif.LdifClient
    ) -> None:
        invalid_entry = m.Ldif.Entry(
            dn=c.Tests.PROCESSING_VALID_DNS[0], attributes=None
        )

        tm.fail(
            api.process_entries(
                [invalid_entry],
                processor_name="transform",
                parallel=False,
                batch_size=1,
                max_workers=1,
            )
        )

    def test_process_entries_parallel_raises_for_none_dn(
        self, api: p.Ldif.LdifClient
    ) -> None:
        invalid_entry = m.Ldif.Entry(
            dn=None, attributes=m.Ldif.Attributes(attributes={"cn": ["x"]})
        )

        with pytest.raises(ValueError, match="Entry DN cannot be None"):
            _ = api.process_entries(
                [invalid_entry],
                processor_name="validate",
                parallel=True,
                batch_size=1,
                max_workers=1,
            )

    def test_pipeline_base_dn_filters_out_of_scope_acl_bind_dn(self) -> None:
        # TransformConfig.servers(base_dn=...) flows through the processing
        # pipeline → FlextLdifTransformer → ACL scope filter.
        entry = u.Tests.create_real_entry(
            dn="cn=users,dc=ctbc",
            attributes={
                "objectClass": ["top"],
                "orclaci": [
                    (
                        'access to entry by group="cn=x,dc=other" (browse) '
                        'by group="cn=a,dc=ctbc" (browse)'
                    )
                ],
            },
        )
        config = m.Ldif.TransformConfig.servers(
            source_server="oid", target_server="oud", base_dn="dc=ctbc"
        )

        result = FlextLdifProcessingPipeline(
            transform_config=config, entries_input=[entry]
        ).execute()
        converted: t.MutableSequenceOf[m.Ldif.Entry] = u.Tests.assert_success(result)
        assert converted[0].attributes is not None
        attrs = converted[0].attributes.attributes

        tm.that(
            attrs["aci"],
            eq=[
                (
                    '(targetattr="*")(version 3.0; acl "users Entry by x"; '
                    'allow (read, search) groupdn="ldap:///cn=a,dc=ctbc";)'
                )
            ],
        )
