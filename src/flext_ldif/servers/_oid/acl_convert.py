"""OID ACL parsing — orclaci/orclentrylevelaci line → typed OidAclRule.

Faithful port of the OUD migration oracle parser
(``parse_oid_acl_line`` / ``Parsing.parse_subject``) into flext-ldif. Pure,
side-effect-free: a malformed ACL surfaces as ``r.fail`` (never a silent skip).
Patterns/permission taxonomy are the ``c.Ldif`` SSOT; models are ``m.Ldif``.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Sequence

from flext_ldif import c, m, p, r
from flext_ldif.servers._oid import FlextLdifConstantsServersOid


class FlextLdifServersOidAclConvert:
    """Parse OID ACL lines into typed :class:`m.Ldif.OidAclRule` value objects."""

    @staticmethod
    def subject_matcher_catalog() -> p.Ldif.AclSubjectMatcherCatalog:
        """Return the typed subject matcher catalog for OID by-clause parsing."""
        return m.Ldif.AclSubjectMatcherCatalog(
            matchers=(
                m.Ldif.AclSubjectMatcher(
                    pattern=c.Ldif.SUBJ_SUPERUSER_RE,
                    subj_type="superuser",
                    value_group="cn=Directory Manager",
                    perms_group=1,
                ),
                m.Ldif.AclSubjectMatcher(
                    pattern=c.Ldif.SUBJ_GROUP_RE,
                    subj_type="group",
                    value_group=1,
                    perms_group=2,
                ),
                m.Ldif.AclSubjectMatcher(
                    pattern=c.Ldif.SUBJ_DN_RE,
                    subj_type=c.ContextScope.USER,
                    value_group=1,
                    perms_group=2,
                ),
                m.Ldif.AclSubjectMatcher(
                    pattern=c.Ldif.SUBJ_QUOTED_DN_RE,
                    subj_type=c.ContextScope.USER,
                    value_group=1,
                    perms_group=2,
                ),
                m.Ldif.AclSubjectMatcher(
                    pattern=c.Ldif.SUBJ_SELF_RE,
                    subj_type="self",
                    value_group="self",
                    perms_group=1,
                ),
                m.Ldif.AclSubjectMatcher(
                    pattern=c.Ldif.SUBJ_ANYONE_RE,
                    subj_type="anyone",
                    value_group="anyone",
                    perms_group=1,
                ),
                m.Ldif.AclSubjectMatcher(
                    pattern=c.Ldif.SUBJ_DNATTR_RE,
                    subj_type="dnattr",
                    value_group=1,
                    perms_group=2,
                ),
                m.Ldif.AclSubjectMatcher(
                    pattern=c.Ldif.SUBJ_GROUPATTR_RE,
                    subj_type="groupattr",
                    value_group=1,
                    perms_group=2,
                ),
                m.Ldif.AclSubjectMatcher(
                    pattern=c.Ldif.SUBJ_GUIDATTR_RE,
                    subj_type="guidattr",
                    value_group=1,
                    perms_group=2,
                ),
            ),
        )

    @staticmethod
    def _split_perms(raw: str) -> Sequence[str]:
        return tuple(token.strip() for token in raw.split(",") if token.strip())

    @staticmethod
    def _subject_modifiers(subject_str: str) -> p.Ldif.OidAclSubjectModifiers:
        bindmode = ""
        bindipfilter = ""
        added_object_constraint = ""
        for modifier in c.Ldif.SUBJ_MODIFIER_RE.finditer(subject_str):
            value = modifier.group(2) or modifier.group(3) or ""
            match modifier.group(1).lower():
                case "bindmode":
                    bindmode = value
                case "bindipfilter":
                    bindipfilter = value
                case "added_object_constraint":
                    added_object_constraint = value
                case "constraintonaddedobject":
                    added_object_constraint = value
                case _:
                    continue
        return m.Ldif.OidAclSubjectModifiers(
            bindmode=bindmode,
            bindipfilter=bindipfilter,
            added_object_constraint=added_object_constraint,
        )

    @classmethod
    def parse_subject(cls, subject_str: str) -> p.Ldif.OidAclSubject:
        """Identify one ``by <subject> (perms)`` clause as a typed subject.

        Returns ``subject_type="unknown"`` when no matcher applies; the line
        parser fails on it.

        Returns:
            The resulting ``m.Ldif.OidAclSubject``.

        """
        text = subject_str.strip()
        modifiers = cls._subject_modifiers(text)
        for matcher in cls.subject_matcher_catalog().matchers:
            match = matcher.pattern.match(text)
            if match is None:
                continue
            value = (
                match.group(matcher.value_group)
                if isinstance(matcher.value_group, int)
                else matcher.value_group
            )
            return m.Ldif.OidAclSubject(
                subject_type=matcher.subj_type,
                value=str(value) if value else "",
                permissions=cls._split_perms(match.group(matcher.perms_group) or ""),
                bindmode=modifiers.bindmode,
                bindipfilter=modifiers.bindipfilter,
                added_object_constraint=modifiers.added_object_constraint,
            )
        return m.Ldif.OidAclSubject(subject_type="unknown")

    @classmethod
    def _strip_acl_prefix(cls, line: str) -> tuple[str, str] | None:
        for acl_type in (
            c.Ldif.AclConvertType.ORCLACI,
            c.Ldif.AclConvertType.ORCLENTRYLEVELACI,
        ):
            prefix = f"{acl_type.value}:"
            if line.startswith(prefix):
                return acl_type.value, line[len(prefix) :].strip()
        return None

    @classmethod
    def _parse_target(cls, content: str) -> tuple[str, str, str] | None:
        """Return ``(target_type, target_attrs, remaining_content)`` or None."""
        lowered = content.lower()
        if lowered.startswith(c.Ldif.AclTargetType.ENTRY):
            rest = content[len(c.Ldif.AclTargetType.ENTRY) :].strip()
            return c.Ldif.AclTargetType.ENTRY.value, c.Ldif.ACL_WILDCARD, rest
        if lowered.startswith(c.Ldif.AclTargetType.ATTR):
            match = c.Ldif.ATTR_PATTERN_RE.match(content)
            if match is None:
                return c.Ldif.AclTargetType.ATTR.value, c.Ldif.ACL_WILDCARD, content
            operator, attrs = match.group(1), match.group(2)
            target_attrs = (
                f"!={attrs}" if operator == "!=" else (attrs or c.Ldif.ACL_WILDCARD)
            )
            return (
                c.Ldif.AclTargetType.ATTR.value,
                target_attrs,
                content[match.end() :].strip(),
            )
        return None

    @classmethod
    def _extract_filter(cls, content: str) -> p.Result[tuple[str | None, str]]:
        """Balanced-paren scan of a ``filter=(...)`` clause → ``(filter, rest)``.

        Returns:
            The resulting ``p.Result[tuple[str | None, str]]``.

        """
        prefix = c.Ldif.FILTER_PREFIX_RE.match(content)
        if prefix is None:
            return r[tuple[str | None, str]].ok((None, content))
        start = prefix.end() - 1
        depth = 0
        end: int | None = None
        for index, char in enumerate(content[start:], start):
            if char == "(":
                depth += 1
            elif char == ")":
                depth -= 1
                if depth == 0:
                    end = index + 1
                    break
        if end is None:
            return r[tuple[str | None, str]].fail(
                f"Unbalanced ACL filter clause: {content[:40]!r}",
            )
        return r[tuple[str | None, str]].ok((
            content[start + 1 : end - 1],
            content[end:].strip(),
        ))

    @classmethod
    def _parse_acl_header(cls, line: str) -> p.Result[tuple[str, str]]:
        """Strip the OID ACL prefix and the mandatory ``access to`` keyword.

        Returns:
            The resulting ``p.Result[tuple[str, str]]``.

        """
        prefixed = cls._strip_acl_prefix(line)
        if prefixed is None:
            return r[tuple[str, str]].fail(f"Not an OID ACL line: {line[:40]!r}")
        acl_type, content = prefixed
        if not content.lower().startswith(c.Ldif.ACL_ACCESS_TO):
            return r[tuple[str, str]].fail(
                f"ACL missing '{c.Ldif.ACL_ACCESS_TO}': {content[:40]!r}",
            )
        return r[tuple[str, str]].ok((
            acl_type,
            content[len(c.Ldif.ACL_ACCESS_TO) :].strip(),
        ))

    @classmethod
    def _parse_acl_target_and_filter(
        cls,
        content: str,
    ) -> p.Result[tuple[str, str, str | None, str]]:
        """Parse the target clause plus the optional balanced filter.

        Returns:
            The resulting ``p.Result[tuple[str, str, str | None, str]]``.

        """
        target = cls._parse_target(content)
        if target is None:
            return r[tuple[str, str, str | None, str]].fail(
                f"Unknown ACL target: {content[:40]!r}",
            )
        target_type, target_attrs, content = target
        filter_result = cls._extract_filter(content)
        if filter_result.failure:
            return r[tuple[str, str, str | None, str]].from_failure(filter_result)
        target_filter, remaining = filter_result.value
        return r[tuple[str, str, str | None, str]].ok((
            target_type,
            target_attrs,
            target_filter,
            remaining,
        ))

    @staticmethod
    def _unrecognized(text: str) -> p.Result[tuple[p.Ldif.OidAclSubject, ...]]:
        """Fail on ACL text outside every recognized by-clause.

        Returns:
            The typed failure naming an object keyword when one is present.

        """
        keyword = FlextLdifConstantsServersOid.OID_ACL_OBJECT_KEYWORD_RE.search(text)
        if keyword is not None:
            return r[tuple[p.Ldif.OidAclSubject, ...]].fail(
                f"OID object keyword {keyword.group(1)!r} has no per-rule OUD "
                f"ACI equivalent (manual review required): {text!r}",
            )
        return r[tuple[p.Ldif.OidAclSubject, ...]].fail(
            f"Unrecognized OID ACL text (manual review required): {text!r}",
        )

    @classmethod
    def _parse_by_clauses(
        cls,
        content: str,
    ) -> p.Result[tuple[p.Ldif.OidAclSubject, ...]]:
        """Parse every ``by`` clause, consuming the whole remaining text.

        Text between or around the clauses that is not a recognized clause
        fails, as does a clause no subject matcher recognizes. The object
        keywords ``DenyGroupOverride`` (blocks superuser and
        DirectoryAdminGroup overrides, which OUD decides by privileges, not
        ACIs; OID-30 §30.1.3.4.2) and ``AppendToAll`` (appends the subject to
        every ACI of the ACP; §30.1.4.1) have no per-rule OUD ACI form and
        fail too.

        Returns:
            The parsed subjects in input order, or the typed failure.

        """
        subjects: list[p.Ldif.OidAclSubject] = []
        cursor = 0
        for clause in c.Ldif.BY_CLAUSE_RE.finditer(content):
            gap = content[cursor : clause.start()].strip()
            cursor = clause.end()
            if gap:
                return cls._unrecognized(gap)
            subject = cls.parse_subject(clause.group(0))
            if subject.subject_type == c.Ldif.OidSubjectKind.UNKNOWN:
                return r[tuple[p.Ldif.OidAclSubject, ...]].fail(
                    f"Unrecognized OID by-clause: {clause.group(0)!r}",
                )
            subjects.append(subject)
        rest = content[cursor:].strip()
        if rest:
            return cls._unrecognized(rest)
        if not subjects:
            return r[tuple[p.Ldif.OidAclSubject, ...]].fail(
                f"No subjects in ACL: {content[:40]!r}",
            )
        return r[tuple[p.Ldif.OidAclSubject, ...]].ok(tuple(subjects))

    @classmethod
    def parse_oid_acl_line(cls, dn: str, line: str) -> p.Result[p.Ldif.OidAclRule]:
        """Parse one full ``orclaci:``/``orclentrylevelaci:`` line into a rule.

        Malformation (wrong prefix, missing ``access to``, unknown target,
        unrecognized text or by-clause, an object keyword without an OUD
        form, or no subjects) surfaces as ``r.fail`` — never a silent drop.

        Returns:
            The resulting ``p.Result[p.Ldif.OidAclRule]``.

        """
        line = line.strip()
        header = cls._parse_acl_header(line)
        if header.failure:
            return r[p.Ldif.OidAclRule].from_failure(header)
        acl_type, content = header.value
        parsed_target = cls._parse_acl_target_and_filter(content)
        if parsed_target.failure:
            return r[p.Ldif.OidAclRule].from_failure(parsed_target)
        target_type, target_attrs, target_filter, content = parsed_target.value
        return cls._parse_by_clauses(content).map(
            lambda subjects: m.Ldif.OidAclRule(
                dn=dn,
                acl_type=acl_type,
                target_type=target_type,
                target_attrs=target_attrs,
                target_filter=target_filter,
                subjects=subjects,
                raw_line=line,
            ),
        )


__all__: list[str] = ["FlextLdifServersOidAclConvert"]
