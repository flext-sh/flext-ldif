"""Master class for all LDIF parsing utilities."""

from __future__ import annotations

import struct
from collections.abc import Callable, MutableMapping, MutableSequence

from flext_core import FlextLogger, r
from flext_ldif import m, t

logger = FlextLogger.create_module_logger(__name__)


class FlextLdifUtilitiesParsers:
    """Master class for all LDIF parsing utilities — flat MRO methods."""

    @staticmethod
    def parse_entry(
        ldif_content: str,
        server_type: str,
        parse_attributes_hook: Callable[
            [MutableSequence[str]],
            MutableMapping[str, MutableSequence[str]],
        ],
        *,
        parse_dn_hook: Callable[[str], str | None] | None = None,
        transform_entry_hook: Callable[[m.Ldif.Entry], m.Ldif.Entry] | None = None,
        parse_comments_hook: Callable[
            [MutableSequence[str]],
            MutableMapping[str, MutableSequence[str]],
        ]
        | None = None,
    ) -> r[m.Ldif.Entry]:
        """Parse LDIF entry from content using hooks."""
        try:
            lines = ldif_content.strip().split("\n")
            dn: str | None = None
            attributes: MutableMapping[str, MutableSequence[str]] = {}
            for line in lines:
                if line.lower().startswith("dn:"):
                    if parse_dn_hook:
                        dn = parse_dn_hook(line)
                    else:
                        dn = line.split(":", 1)[1].strip()
                    break
            if dn is None:
                return r[m.Ldif.Entry].fail("No DN found in LDIF content")
            attributes = dict(parse_attributes_hook(lines))
            if parse_comments_hook:
                comments = parse_comments_hook(lines)
                attributes.update(comments)
            dn_obj = m.Ldif.DN(value=dn)
            attrs_obj = m.Ldif.Attributes.model_validate({"attributes": attributes})
            entry = m.Ldif.Entry(dn=dn_obj, attributes=attrs_obj)
            if transform_entry_hook:
                entry = transform_entry_hook(entry)
            return r[m.Ldif.Entry].ok(entry)
        except (
            ValueError,
            KeyError,
            AttributeError,
            UnicodeDecodeError,
            struct.error,
        ) as e:
            logger.exception("Failed to parse entry", server_type=server_type)
            return r[m.Ldif.Entry].fail(f"Failed to parse entry: {e}")

    @staticmethod
    def parse_attribute_definition(
        definition: str,
        server_type: str,
        parse_parts_hook: Callable[[str], t.MutableOptionalFeatureFlagMapping],
        *,
        transform_hook: Callable[[m.Ldif.SchemaAttribute], m.Ldif.SchemaAttribute]
        | None = None,
        parse_oid_hook: Callable[[str], str | None] | None = None,
    ) -> r[m.Ldif.SchemaAttribute]:
        """Parse attribute definition using hooks."""
        try:
            parts = parse_parts_hook(definition)
            oid = parts.get("oid", "")
            if parse_oid_hook:
                parsed_oid = parse_oid_hook(definition)
                if parsed_oid:
                    oid = parsed_oid
            attribute = m.Ldif.SchemaAttribute(
                oid=str(oid) if oid else "",
                name=str(parts.get("name", oid or "")),
                desc=str(parts.get("desc")) if parts.get("desc") else None,
                syntax=str(parts.get("syntax")) if parts.get("syntax") else None,
                equality=str(parts.get("equality")) if parts.get("equality") else None,
                ordering=str(parts.get("ordering")) if parts.get("ordering") else None,
                substr=str(parts.get("substr")) if parts.get("substr") else None,
                single_value=bool(parts.get("single_value", False)),
                no_user_modification=bool(parts.get("no_user_modification", False)),
                sup=str(parts.get("sup")) if parts.get("sup") else None,
                usage=str(parts.get("usage")) if parts.get("usage") else None,
            )
            if transform_hook:
                attribute = transform_hook(attribute)
            return r[m.Ldif.SchemaAttribute].ok(attribute)
        except (
            ValueError,
            KeyError,
            AttributeError,
            UnicodeDecodeError,
            struct.error,
        ) as e:
            logger.exception("Failed to parse attribute", server_type=server_type)
            return r[m.Ldif.SchemaAttribute].fail(f"Failed to parse attribute: {e}")

    @staticmethod
    def parse_objectclass_definition(
        definition: str,
        server_type: str,
        parse_parts_hook: Callable[
            [str],
            MutableMapping[str, str | MutableSequence[str] | None],
        ],
        *,
        transform_hook: Callable[
            [m.Ldif.SchemaObjectClass],
            m.Ldif.SchemaObjectClass,
        ]
        | None = None,
    ) -> r[m.Ldif.SchemaObjectClass]:
        """Parse objectClass definition using hooks."""
        try:
            parts = parse_parts_hook(definition)
            must_raw = parts.get("must")
            must: MutableSequence[str] | None
            if isinstance(must_raw, list):
                must = [str(item) for item in must_raw]
            elif must_raw is None:
                must = None
            else:
                must = [str(must_raw)]
            may_raw = parts.get("may")
            may: MutableSequence[str] | None
            if isinstance(may_raw, list):
                may = [str(item) for item in may_raw]
            elif may_raw is None:
                may = None
            else:
                may = [str(may_raw)]
            objectclass = m.Ldif.SchemaObjectClass(
                oid=str(parts.get("oid", "")),
                name=str(parts.get("name", parts.get("oid", ""))),
                desc=str(parts.get("desc")) if parts.get("desc") else None,
                sup=str(parts.get("sup")) if parts.get("sup") else None,
                kind=str(parts.get("kind", "STRUCTURAL")),
                must=must,
                may=may,
            )
            if transform_hook:
                objectclass = transform_hook(objectclass)
            return r[m.Ldif.SchemaObjectClass].ok(objectclass)
        except (
            ValueError,
            KeyError,
            AttributeError,
            UnicodeDecodeError,
            struct.error,
        ) as e:
            logger.exception("Failed to parse objectClass", server_type=server_type)
            return r[m.Ldif.SchemaObjectClass].fail(
                f"Failed to parse objectClass: {e}",
            )

    @staticmethod
    def parse_content(
        ldif_content: str,
        server_type: str,
        parse_entry_hook: Callable[[str], r[m.Ldif.Entry]],
        *,
        _parse_header_hook: Callable[[str], MutableMapping[str, str]] | None = None,
    ) -> r[MutableSequence[m.Ldif.Entry]]:
        """Parse multiple entries from LDIF content."""
        try:
            entries: MutableSequence[m.Ldif.Entry] = []
            raw_entries = ldif_content.strip().split("\n\n")
            successful = 0
            failed = 0
            for raw_entry in raw_entries:
                if not raw_entry.strip():
                    continue
                processed_entry = ""
                lines = raw_entry.strip().split("\n")
                if lines and lines[0].lower().startswith("version:"):
                    lines = lines[1:]
                    if not lines:
                        continue
                    processed_entry = "\n".join(lines)
                else:
                    processed_entry = raw_entry.strip()
                result = parse_entry_hook(processed_entry)
                if result.is_success:
                    successful += 1
                    entries.append(result.value)
                else:
                    failed += 1
                    logger.warning(
                        "Failed to parse entry",
                        error=str(result.error),
                        server_type=server_type,
                    )
            logger.debug(
                "LDIF content parse stats",
                total_entries=len(raw_entries),
                successful=successful,
                failed=failed,
            )
            return r[MutableSequence[m.Ldif.Entry]].ok(entries)
        except (
            ValueError,
            KeyError,
            AttributeError,
            UnicodeDecodeError,
            struct.error,
        ) as e:
            logger.exception("Failed to parse content", server_type=server_type)
            return r[MutableSequence[m.Ldif.Entry]].fail(
                f"Failed to parse content: {e}",
            )


__all__ = ["FlextLdifUtilitiesParsers"]
