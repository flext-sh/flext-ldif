# OID to OUD ACL conversion rules

<!-- TOC START -->

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
  and `*,<dn>` is the strict subtree of the DN. A group grants only when it is an exact
  security group of the injected source directory (OID-30 §30.1.3.4.6). `SuperUser` and
  `guidattr` match no OUD session. `bindmode` and `bindipfilter` fail unless the form is
  `*` with `bindmode=Proxy`.

## 2. Policy evaluation

Implemented in `acl_assemble.py`, following the OID evaluation model (OID-30 §30.1.6).

- **R8**: a by-clause subject without a rule fails.
- **R7**: an `AppendToAll` clause joins every other ACI of its access control point
  (ACP).
- **R6a**: inside one ACI, a grant from any matching clause wins over a matching denial
  (OID-30 §30.1.6.2; examples §30.3.6 and §30.3.9).
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
  `targetfilter`. A proxy grant keeps the source scope and is reported for review until
  its OUD target is measured.
- **R5**: every denial below the root DSE becomes a `deny` that excludes the subjects its
  ACI grants (R6a) and the privilege groups a farther ACP grants, placed by region (§3).
- **R6b**: a named attribute leaves the ACP's `*` ACI; a filtered ACI decides before the
  unfiltered one where its filter matches.
- **R8**: a grant to OID `*` goes to `ldap:///all` and a denial to `ldap:///anyone`.
- **R9**: root DSE `orclaci` grants land on the suffix root; its denials emit nothing.
