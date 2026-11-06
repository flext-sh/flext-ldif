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
                    pattern=FlextLdifConstantsServersOid.OID_SUBJ_SUPERUSER_RE,
                    subj_type="superuser",
                    value_group=c.Ldif.OidSubjectKind.SUPERUSER.value,
                    perms_group=1,
                ),
                m.Ldif.AclSubjectMatcher(
                    pattern=FlextLdifConstantsServersOid.OID_SUBJ_GROUP_RE,
                    subj_type="group",
                    value_group=1,
                    perms_group=2,
                ),
                m.Ldif.AclSubjectMatcher(
                    pattern=FlextLdifConstantsServersOid.OID_SUBJ_DN_RE,
                    subj_type=c.ContextScope.USER,
                    value_group=1,
                    perms_group=2,
                ),
                m.Ldif.AclSubjectMatcher(
                    pattern=FlextLdifConstantsServersOid.OID_SUBJ_QUOTED_DN_RE,
                    subj_type=c.ContextScope.USER,
                    value_group=1,
                    perms_group=2,
                ),
                m.Ldif.AclSubjectMatcher(
                    pattern=FlextLdifConstantsServersOid.OID_SUBJ_SELF_RE,
                    subj_type="self",
                    value_group="self",
                    perms_group=1,
                ),
                m.Ldif.AclSubjectMatcher(
                    pattern=FlextLdifConstantsServersOid.OID_SUBJ_ANYONE_RE,
                    subj_type="anyone",
                    value_group="anyone",
                    perms_group=1,
                ),
                m.Ldif.AclSubjectMatcher(
                    pattern=FlextLdifConstantsServersOid.OID_SUBJ_DNATTR_RE,
                    subj_type="dnattr",
                    value_group=1,
                    perms_group=2,
                ),
                m.Ldif.AclSubjectMatcher(
                    pattern=FlextLdifConstantsServersOid.OID_SUBJ_GROUPATTR_RE,
                    subj_type="groupattr",
                    value_group=1,
                    perms_group=2,
                ),
                m.Ldif.AclSubjectMatcher(
                    pattern=FlextLdifConstantsServersOid.OID_SUBJ_GUIDATTR_RE,
                    subj_type="guidattr",
                    value_group=1,
                    perms_group=2,
                ),
            ),
        )

    @staticmethod
    def _split_perms(raw: str) -> Sequence[str]:
        """Split an access list on commas, keeping empty tokens for rejection.

        Returns:
            The stripped tokens; an all-blank list yields none.

        """
        if not raw.strip():
            return ()
        return tuple(token.strip() for token in raw.split(","))

    @staticmethod
    def subject_modifiers(
        subject_str: str,
    ) -> p.Result[p.Ldif.OidAclSubjectModifiers]:
        """Read the optional modifiers of one ``by`` clause.

        Each modifier may appear once per clause with a non-empty value; a
        repeated or empty modifier surfaces as ``r.fail``.

        Returns:
            The typed modifiers, or the typed failure.

        """
        constants = FlextLdifConstantsServersOid
        result = r[p.Ldif.OidAclSubjectModifiers]
        modifiers = m.Ldif.OidAclSubjectModifiers()
        seen: set[str] = set()
        for modifier in constants.OID_SUBJ_MODIFIER_RE.finditer(subject_str):
            name = modifier.group(1)
            kind = name.lower()
            if kind in constants.OID_ADDED_OBJECT_MODIFIERS:
                kind = c.Ldif.ACL_CONSTRAINT
            value = (modifier.group(2) or modifier.group(3) or "").strip()
            if not value:
                return result.fail(
                    f"Empty OID {name!r} modifier in by-clause "
                    f"(manual review required): {subject_str!r}",
                )
            if kind in seen:
                return result.fail(
                    f"Repeated OID {name!r} modifier in by-clause "
                    f"(manual review required): {subject_str!r}",
                )
            seen.add(kind)
            modifiers = modifiers.model_copy(update={kind: value})
        return result.ok(modifiers)

    @classmethod
    def parse_subject(cls, subject_str: str) -> p.Ldif.OidAclSubject:
        """Identify one ``by <subject> (perms)`` clause as a typed subject.

        Returns ``subject_type="unknown"`` when no matcher applies or a
        modifier is repeated or empty; the line parser fails on it.

        Returns:
            The resulting ``m.Ldif.OidAclSubject``.

        """
        text = subject_str.strip()
        modifiers = cls.subject_modifiers(text)
        if modifiers.failure:
            return m.Ldif.OidAclSubject(subject_type=c.Ldif.OidSubjectKind.UNKNOWN)
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
                bindmode=modifiers.value.bindmode,
                bindipfilter=modifiers.value.bindipfilter,
                added_object_constraint=modifiers.value.added_object_constraint,
            )
        return m.Ldif.OidAclSubject(subject_type=c.Ldif.OidSubjectKind.UNKNOWN)

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
    def _parse_target(cls, content: str) -> p.Result[tuple[str, str, str]]:
        """Read the ``<object>`` target: ``entry``, ``attr=*`` or an attribute list.

        The OID BNF is ``attr <EQ-OR-NEQ> ( * | (<attrList>) ) | entry``
        (OID-A7 §A.7.1); ``attr=(*)`` is the parenthesized wildcard. Any other
        ``attr`` text, and ``attr!=*``, surface as ``r.fail``.

        Returns:
            ``(target_type, target_attrs, remaining_content)``, or the failure.

        """
        result = r[tuple[str, str, str]]
        lowered = content.lower()
        if lowered.startswith(c.Ldif.AclTargetType.ENTRY):
            rest = content[len(c.Ldif.AclTargetType.ENTRY) :].strip()
            return result.ok((
                c.Ldif.AclTargetType.ENTRY.value,
                c.Ldif.ACL_WILDCARD,
                rest,
            ))
        if not lowered.startswith(c.Ldif.AclTargetType.ATTR):
            return result.fail(f"Unknown ACL target: {content[:40]!r}")
        match = FlextLdifConstantsServersOid.OID_ATTR_TARGET_RE.match(content)
        if match is None:
            return result.fail(
                f"OID attribute target {content[:40]!r} is neither attr=* nor "
                "attr[!]=(<attrList>) (OID-A7 §A.7.1; manual review required)",
            )
        operator, listed, star = match.group(1), match.group(2), match.group(3)
        attrs = (listed if listed is not None else star or "").strip()
        if operator == c.Ldif.OUD_ATTR_NEGATION and attrs == c.Ldif.ACL_WILDCARD:
            return result.fail(
                f"OID attribute target {match.group(0)!r} negates every attribute "
                "and names no target (OID-A7 §A.7.1; manual review required)",
            )
        target_attrs = f"!={attrs}" if operator == c.Ldif.OUD_ATTR_NEGATION else attrs
        return result.ok((
            c.Ldif.AclTargetType.ATTR.value,
            target_attrs,
            content[match.end() :].strip(),
        ))

    @staticmethod
    def _check_target_attrs(target_attrs: str) -> p.Result[bool]:
        """Accept ``*`` or a list of attribute descriptions, optionally negated.

        An empty list, an empty element, ``*`` inside a list or a negated
        ``*`` has no exact OUD targetattr and surfaces as ``r.fail``, as does
        any element outside the attribute-description grammar.

        Returns:
            Success, or the typed failure.

        """
        negation = c.Ldif.OUD_ATTR_NEGATION
        body = target_attrs.removeprefix(negation)
        if body == c.Ldif.ACL_WILDCARD and body == target_attrs:
            return r[bool].ok(value=True)
        names = [name.strip() for name in body.split(",")]
        descriptor = FlextLdifConstantsServersOid.OID_ATTR_DESCRIPTOR_RE
        if not all(descriptor.match(name) for name in names):
            return r[bool].fail(
                f"OID attribute target {target_attrs!r} is not '*' or a list of "
                "attribute descriptions (manual review required)",
            )
        return r[bool].ok(value=True)

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
        if target.failure:
            return r[tuple[str, str, str | None, str]].from_failure(target)
        target_type, target_attrs, content = target.value
        attrs_check = cls._check_target_attrs(target_attrs)
        if attrs_check.failure:
            return r[tuple[str, str, str | None, str]].from_failure(attrs_check)
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
                f"OID object keyword {keyword.group(1)!r} outside its BNF position "
                f"after the target and filter (OID-A7 §A.7.1; manual review "
                f"required): {text!r}",
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
        keywords are read before the first clause
        (:meth:`_parse_object_keywords`); one found here fails.

        Returns:
            The parsed subjects in input order, or the typed failure.

        """
        subjects: list[p.Ldif.OidAclSubject] = []
        cursor = 0
        for clause in FlextLdifConstantsServersOid.OID_BY_CLAUSE_RE.finditer(content):
            gap = content[cursor : clause.start()].strip()
            cursor = clause.end()
            if gap:
                return cls._unrecognized(gap)
            modifiers = cls.subject_modifiers(clause.group(0))
            if modifiers.failure:
                return r[tuple[p.Ldif.OidAclSubject, ...]].from_failure(modifiers)
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

        The object keywords ``DenyGroupOverride`` and ``AppendToAll`` follow
        the target and the filter (OID-A7 §A.7.1) and are recorded on the
        rule. Malformation (wrong prefix, missing ``access to``, unknown
        target, unrecognized text or by-clause, a misplaced object keyword,
        or no subjects) surfaces as ``r.fail`` — never a silent drop.

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
        keywords = FlextLdifConstantsServersOid.OID_ACL_OBJECT_KEYWORDS_RE.match(
            content
        )
        deny_group_override = bool(keywords and keywords.group("dgo"))
        append_to_all = bool(keywords and keywords.group("ata"))
        remaining = content[keywords.end() :] if keywords else content
        return cls._parse_by_clauses(remaining).map(
            lambda subjects: m.Ldif.OidAclRule(
                dn=dn,
                acl_type=acl_type,
                target_type=target_type,
                target_attrs=target_attrs,
                target_filter=target_filter,
                subjects=subjects,
                raw_line=line,
                deny_group_override=deny_group_override,
                append_to_all=append_to_all,
            ),
        )


__all__: list[str] = ["FlextLdifServersOidAclConvert"]
