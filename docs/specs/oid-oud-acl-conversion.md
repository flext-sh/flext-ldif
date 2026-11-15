# OID to OUD ACL conversion rules

<!-- TOC START -->

- [1. Primitives](#1-primitives)
- [2. Policy evaluation](#2-policy-evaluation)
- [3. Denial region (R5)](#3-denial-region-r5)
- [4. Emission](#4-emission)

<!-- TOC END -->

This specification is owned by flext-ldif. It states the rules R1 to R9 that
`flext_ldif.servers._oid` applies when it converts Oracle Internet Directory (OID)
access control (`orclaci`, `orclentrylevelaci`) into Oracle Unified Directory (OUD)
ACI statements. OID behaviour is cited from the Oracle Internet Directory
Administrator's Guide, chapter 30 (OID-30). A form that no rule covers fails with
`r.fail`; nothing is approximated or dropped in silence.

## 1. Primitives

Implemented in `acl_convert_oud.py`.

- OID access lists resolve to granted and denied OID rights (OID-30 §30.1.4.3).
- **R1**: an attribute target becomes an OUD `targetattr` set, case folded.
- **R8**: each OID subject becomes one OUD bind-rule leaf, or matches no session.
  `*` is `anyone` (granted as `all`), `self` is `self`, `dnattr=(a)` is
  `userattr="a#USERDN"`, `groupattr=(a)` is `userattr="a#GROUPDN"`, a DN is literal
  and `*,<dn>` is the strict subtree of the DN; `.*<dn>` without a comma (Oracle's own
  seeded ACLs, `by dn=".*cn=Reports,cn=Products,cn=OracleContext"`) is the DN itself
  and its subtree, `userdn="ldap:///<dn>??sub?(objectclass=*)"` (both forms measured
  on OID 12.2.1.4). A group grants only when it is an exact security group of the
  injected source directory (OID-30 §30.1.3.4.6). `group="G"` names a literal DN
  (OID-A7 §A.7.1): a group absent from the source, also one whose literal value
  carries `*` (Oracle's seeded `group="cn=bindaplicacao,ou=*,…"`), has no members and
  matches no session, recorded as a conversion event; measured on OID 12.2.1.4 (a
  member of a group the pattern names is not granted) and on OUD 14.1.2.1 (a
  `groupdn` with `*` is accepted but matches nobody). `SuperUser` and
  `guidattr` match no OUD session. `bindmode` and `bindipfilter` fail unless the form is
  `*` with `bindmode=Proxy`.

## 2. Policy evaluation

Implemented in `acl_assemble.py`, following the OID evaluation model (OID-30 §30.1.6).

- **R8**: a by-clause subject without a rule fails.
- **R7**: an `AppendToAll` clause joins every other ACI of its access control point
  (ACP).
- **R6a**: in one level, the clauses of the specific subjects that match a session
  decide and the level's `*` clauses are not consulted for any right; only when no
  specific subject matches does `*` decide. Among the clauses that decide, a denial
  beats a grant in any order and across the level's ACIs; a right they leave
  undecided falls to the next level. Measured on OID 12.2.1.4
  (`lab/oid/measurements/2026-11-15-acl-precedence.md` in algar-oud-mig); the grant-wins
  reading of OID-30 §30.1.6.2 does not match the server. A plain group (no
  `orclPrivilegeGroup`/`orclACPgroup`) matches no session (measured), and `(none)`
  denies every right (measured against the seeded root grant of browse).
- **R6b**: ACIs of one level with an identical object string are one ACI.

## 3. Denial region (R5)

Implemented in `acl_region.py`. The policy is indexed by evaluation level: the entry's
`orclEntryLevelACI`, then each ACP up to the root DSE. Each OUD `deny` is placed so that
the levels OID evaluates first still decide inside their region:

- a nearer grant whose subject no farther ACP grants is excluded from the whole denial;
- the anchor's own entry-level ACI splits the scope (`base` and `subordinate`; for add,
  `onelevel` and `target="*,*,P"`);
- an entry-level ACI below leaves through `(!(entryDN=V))` and gets its own `base`
  denial; an ACP below leaves through `target!=` and the denial is placed again inside
  it;
- two or more sibling ACP subtrees split the denial over the anchor's current children,
  read from the injected directory.

These forms were measured on OUD 14.1.2.1; any other overlap fails.

## 4. Emission

Implemented in `acl_render.py`.

- **R1, R2, R3**: attribute grants keep the origin scope (`orclaci` subtree,
  `orclentrylevelaci` base) and the filter as `targetfilter`; read and compare are
  granted only where OID decides browse for the subject (OID-30 Tables 30-2 and 30-3).
- **R4**: entry rights are separate ACIs. Add uses `subordinate`/`onelevel`
  (`dnattr` reads the new entry's parent), delete keeps the origin scope, browse becomes
  `objectClass` read plus search, and the added-object constraint becomes the add
  `targetfilter` (measured on OID 12.2.1.4: the constraint is decided on the new
  entry). `self` on add (the bind DN equals the parent) has no OUD form and fails,
  granted, denied or left to the next level. A delete `filter=` is decided on the
  deleted entry (measured). A proxy grant keeps the source scope and is reported for
  review until its OUD target is measured.
- **E7** (filter on add): OID decides an entry ACI's `filter=` on the entry the
  operation acts on; for add that is the parent, and in an ACP every parent of the
  subtree counts (measured on OID 12.2.1.4: a matching parent and its matching
  descendants admit the add, a non-matching parent does not). OUD's add `targetfilter`
  matches the new entry, so the add, grant or denial, is placed with
  `targetscope="onelevel"` on each existing parent the filter matches: the ACP entry and
  its descendants, or the `orclentrylevelaci` entry alone. The filter is evaluated on the
  migrated entries (equality, presence, substrings, `&`, `|`, `!`, case-insensitive);
  any other assertion fails. Measured on OUD 14.1.2.1: the converted policy admits and
  refuses the same adds as the OID. Inherent difference: a matching parent created after
  the migration is not covered; each rule reports it as an event.
- **R5**: every denial below the root DSE becomes a `deny`. A specific subject's denial
  excludes nobody; a `*` denial excludes the specific subjects of the ACI that do not
  deny the right (R6a). Both exclude the privilege groups a farther ACP grants
  (measured on OID 12.2.1.4: a farther privilege-group grant lifts a nearer denial,
  even the group's own, unless the denying level carries `DenyGroupOverride`), placed
  by region (§3).
- **R6a** (grant side): a `*` grant excludes the specific subjects of the ACI that leave
  the right undecided, `allow (r) (userdn="ldap:///all" and not …)`. Such a grant beside
  a farther denial, or under a filter, has no exact placement and fails.
- **R6b**: a named attribute leaves the ACP's `*` ACI; a filtered ACI decides before the
  unfiltered one where its filter matches.
- **R8**: a grant to OID `*` goes to `ldap:///all` and a denial to `ldap:///anyone`.
- **R9**: root DSE `orclaci` grants land on the suffix root; its denials emit nothing.
