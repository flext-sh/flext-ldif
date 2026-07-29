"""OID ACL parsing — orclaci/orclentrylevelaci line → typed OidAclRule.

Faithful port of the OUD migration oracle parser
(``parse_oid_acl_line`` / ``Parsing.parse_subject``) into flext-ldif. Pure,
side-effect-free: a malformed ACL surfaces as ``r.fail`` (never a silent skip).
Patterns/permission taxonomy are the ``c.Ldif`` SSOT; models are ``m.Ldif``.
"""

from __future__ import annotations

from flext_ldif import c, m, p, r, t


class FlextLdifServersOidAclConvert:
    """Parse OID ACL lines into typed :class:`m.Ldif.OidAclRule` value objects."""

    @staticmethod
    def subject_matcher_catalog() -> m.Ldif.AclSubjectMatcherCatalog:
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
                    subj_type="user",
                    value_group=1,
                    perms_group=2,
                ),
                m.Ldif.AclSubjectMatcher(
                    pattern=c.Ldif.SUBJ_QUOTED_DN_RE,
                    subj_type="user",
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
            )
        )

    @staticmethod
    def _split_perms(raw: str) -> t.StrSequence:
        return tuple(token.strip() for token in raw.split(",") if token.strip())

    @staticmethod
    def _subject_modifiers(subject_str: str) -> m.Ldif.OidAclSubjectModifiers:
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
    def parse_subject(cls, subject_str: str) -> m.Ldif.OidAclSubject:
        """Identify one ``by <subject> (perms)`` clause as a typed subject.

        Returns ``subject_type="unknown"`` when no matcher applies (the caller
        drops unknown subjects), mirroring the oracle's default contract.
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
        """Balanced-paren scan of a ``filter=(...)`` clause → ``(filter, rest)``."""
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
                f"Unbalanced ACL filter clause: {content[:40]!r}"
            )
        return r[tuple[str | None, str]].ok((
            content[start + 1 : end - 1],
            content[end:].strip(),
        ))

    @classmethod
    def parse_oid_acl_line(cls, dn: str, line: str) -> p.Result[m.Ldif.OidAclRule]:
        """Parse one full ``orclaci:``/``orclentrylevelaci:`` line into a rule.

        Malformation (wrong prefix, missing ``access to``, unknown target, or no
        recognizable subjects) surfaces as ``r.fail`` — never a silent drop.
        """
        line = line.strip()
        prefixed = cls._strip_acl_prefix(line)
        if prefixed is None:
            return r[m.Ldif.OidAclRule].fail(f"Not an OID ACL line: {line[:40]!r}")
        acl_type, content = prefixed
        if not content.lower().startswith(c.Ldif.ACL_ACCESS_TO):
            return r[m.Ldif.OidAclRule].fail(
                f"ACL missing '{c.Ldif.ACL_ACCESS_TO}': {content[:40]!r}"
            )
        content = content[len(c.Ldif.ACL_ACCESS_TO) :].strip()
        target = cls._parse_target(content)
        if target is None:
            return r[m.Ldif.OidAclRule].fail(f"Unknown ACL target: {content[:40]!r}")
        target_type, target_attrs, content = target
        filter_result = cls._extract_filter(content)
        if filter_result.failure:
            return r[m.Ldif.OidAclRule].fail(
                filter_result.error or "Invalid ACL filter clause"
            )
        target_filter, content = filter_result.value
        subjects = tuple(
            subject
            for raw in c.Ldif.BY_CLAUSE_RE.finditer(content)
            if (subject := cls.parse_subject(raw.group(0))).subject_type != "unknown"
        )
        if not subjects:
            return r[m.Ldif.OidAclRule].fail(f"No subjects in ACL: {content[:40]!r}")
        return r[m.Ldif.OidAclRule].ok(
            m.Ldif.OidAclRule(
                dn=dn,
                acl_type=acl_type,
                target_type=target_type,
                target_attrs=target_attrs,
                target_filter=target_filter,
                subjects=subjects,
                raw_line=line,
            )
        )


__all__: list[str] = ["FlextLdifServersOidAclConvert"]
