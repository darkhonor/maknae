//! The assembled configuration document and its provenance types (spec §5/§6).
//! Schema-agnostic: sections are opaque `Value`s; each subsystem parses its own.

use crate::Value;
use std::collections::BTreeMap;
use std::path::PathBuf;

/// A section the caller registers (extensions only — `core` is reserved and
/// injected by the loader, spec §5).
#[derive(Clone, Debug)]
pub struct SectionSpec {
    pub name: String,
    pub required: bool,
}

/// Which source supplied a winning section.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Source {
    Base,
    ConfigD(PathBuf),
}

/// A recorded override: a `config.d/` section shadowed a base section (spec §4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Override {
    pub section: String,
    pub winner: Source,
    pub shadowed: Source,
}

/// The assembled document: named sections + the audit trail of overrides.
#[derive(Debug)]
pub struct Document {
    sections: Vec<(String, Value, Source)>,
    overrides: Vec<Override>,
}

impl Document {
    /// Build a `Document` from sections directly, for tests that need a REAL
    /// one without the ownership-gated file load. Feature-gated and non-default
    /// (the `hermetic-test-seam` pattern used by `load_authz`): the code path
    /// under test -- [`Document::disclosable_view`] -- is the production one,
    /// only the source of the sections is hermetic.
    #[cfg(feature = "hermetic-test-seam")]
    pub fn from_sections_for_test(sections: Vec<(String, Value)>) -> Self {
        Document {
            sections: sections
                .into_iter()
                .map(|(n, v)| (n, v, Source::Base))
                .collect(),
            overrides: Vec::new(),
        }
    }

    /// Loader-only constructor.
    pub(crate) fn new(sections: Vec<(String, Value, Source)>, overrides: Vec<Override>) -> Self {
        Document {
            sections,
            overrides,
        }
    }

    /// The section's `Value`, or `None` for a registered-optional-absent (or
    /// unregistered) name. The subsystem parses the `Value` itself.
    pub fn section(&self, name: &str) -> Option<&Value> {
        self.sections
            .iter()
            .find(|(n, _, _)| n == name)
            .map(|(_, v, _)| v)
    }

    /// The audit trail of which source won each overridden section.
    pub fn overrides(&self) -> &[Override] {
        &self.overrides
    }

    /// The effective configuration as `admin.config.show` may disclose it
    /// (#162 Phase 2, operator ruling 2026-08-31): every section, every key, at
    /// every depth -- and a VALUE only where this crate has declared the field
    /// disclosable. Everything else renders [`MASK`].
    ///
    /// **Deny by default, and that is the entire design.** The obvious
    /// alternative -- a denylist of names that look secret (`*token*`,
    /// `*password*`) -- defaults every future field to DISCLOSED and depends on
    /// whoever adds one remembering to classify it. A rule that depends on
    /// someone remembering is not a control. Here a field added five minutes
    /// ago is masked until a human puts it on [`DISCLOSABLE`], which is a code
    /// change, reviewed, in this file.
    ///
    /// Keys are flattened to dotted paths within a section, so nesting cannot
    /// hide a field from the classifier by depth.
    pub fn disclosable_view(&self) -> BTreeMap<String, BTreeMap<String, String>> {
        let mut out = BTreeMap::new();
        for (name, value, _) in &self.sections {
            let mut flat = BTreeMap::new();
            flatten(DISCLOSABLE, name, "", value, &mut flat);
            // An all-suppressed section emits NOTHING, not an empty map. An
            // empty `core: {}` is distinguishable on the wire from both a
            // populated one and an absent one, and today the only suppressible
            // thing under `core` is `handling` -- so `core: {}` would mean
            // "this deployment has an above-baseline ceiling", which is the
            // exact inference the suppression exists to deny. Omission has to
            // be total to be omission.
            if !flat.is_empty() {
                out.insert(name.clone(), flat);
            }
        }
        out
    }

    /// Fold a subsystem's RESOLVED settings into a view.
    ///
    /// The ruling is "the effective composed settings **as the daemon actually
    /// resolved them**", and a `Document` cannot satisfy that alone: a section
    /// absent from the file -- `transport:` in the shipped skeleton -- is
    /// absent from the `Document` too, while the daemon is very much running on
    /// its defaults. Reporting no `transport` section would tell an operator
    /// the settings do not exist, which is worse than masking them.
    ///
    /// The caller supplies already-resolved values at boot; classification is
    /// unchanged, so an unclassified resolved field still masks.
    pub fn merge_resolved(
        view: &mut BTreeMap<String, BTreeMap<String, String>>,
        section: &str,
        fields: &[(&str, Option<String>)],
    ) {
        // Built locally and merged only if non-empty. `entry().or_default()`
        // materialises the section BEFORE the loop, so an all-suppressed field
        // list would leave `{}` behind -- the same presence bit the file lane
        // was just fixed to stop emitting. Two lanes, one invariant.
        let mut local: BTreeMap<String, String> = BTreeMap::new();
        for (path, value) in fields {
            // SUPPRESSION FIRST, then absence. The file lane composes
            // `Omit -> Null -> Clear/Mask`: `flatten` filters `Omit` before it
            // ever calls `render`, which is the only reason `render`'s early
            // `Null` return is safe. This lane has no outer filter, so the
            // order has to be written here.
            //
            // An earlier version checked absence first and claimed parity with
            // `render`. It did not have it: folding a suppressed path with
            // `None` -- say `vault.insecure_plaintext_secret_path`, an
            // `Option<PathBuf>` sitting one line from the two mounts that ARE
            // folded -- would have emitted the SUPPRESSED KEY as `<not set>` on
            // every correctly-enrolled host, and omitted it on a
            // plaintext-enrolled one. That is round 2's leak with the polarity
            // inverted: the posture disclosed by absence instead of presence.
            if classify(section, path, DISCLOSABLE) == Disclosure::Omit {
                continue;
            }
            //
            // The earlier signature took a bare `String`, so a caller wanting to
            // say "this resolved to nothing" had to invent a sentinel; the
            // `Mask` arm then DISCARDED it and inserted `MASK`. `audit.siem` is
            // withheld, so on the shipped skeleton -- which sets no `siem` --
            // the view reported `<value set>` for an external audit-offload
            // endpoint that does not exist. `MASK` means "configured, not
            // shown"; saying it about an unset field is the exact collapse
            // `NOT_SET` exists to prevent, on a field the same review flagged as
            // credential-bearing. An `Option` makes the state unrepresentable
            // rather than merely discouraged.
            let Some(value) = value else {
                local.insert((*path).to_string(), NOT_SET.to_string());
                continue;
            };
            // The SAME classifier the file walk uses — a resolved default is
            // not privileged for having come from code.
            match classify(section, path, DISCLOSABLE) {
                Disclosure::Omit => unreachable!("filtered above"),
                Disclosure::Clear => local.insert((*path).to_string(), value.clone()),
                Disclosure::Mask => local.insert((*path).to_string(), MASK.to_string()),
            };
        }
        if !local.is_empty() {
            view.entry(section.to_string()).or_default().extend(local);
        }
    }
}

/// Rendered in place of a VALUE this crate has not declared disclosable.
///
/// > **Corrected in place 2026-09-01.** This doc previously read "Says THAT the
/// > setting is configured, never what it is" as an unqualified statement, and
/// > that is **true of a value and false of a key**. Where a field's mere
/// > EXISTENCE is the disclosure -- `vault.insecure_plaintext_secret_path`,
/// > `core.handling.*` -- masking is not enough and the path belongs on
/// > [`SUPPRESSED`], which omits it entirely. The correction was first written
/// > on `SUPPRESSED` instead of here, which left the wrong claim on the item a
/// > reader actually hovers when deciding MASK-vs-SUPPRESSED for a new field --
/// > and that decision is exactly how the plaintext-path leak happened.
///
/// So: this says that the setting **is set** and is not being shown. Reserve it
/// for fields whose presence is unremarkable. For "not set at all", see
/// [`NOT_SET`] -- and never emit this for an absent value, which is a claim
/// that something is configured when it is not.
pub const MASK: &str = "<value set>";

/// Rendered for a key that is present but has no value. Deliberately distinct
/// from [`MASK`]: "not set" and "set to something I will not show you" are
/// different answers to the operator's actual question, and collapsing them
/// makes the disclosure useless for the case it exists to serve.
pub const NOT_SET: &str = "<not set>";

/// Fields whose VALUES `admin.config.show` may disclose in the clear, as
/// `<section>.<dotted path>`.
///
/// Everything absent from this list is masked. Adding an entry is a deliberate
/// disclosure decision: it publishes that value to any subject holding a grant
/// for `admin.config.show`. The bar is that the value is deployment SHAPE an
/// operator cannot debug without, and is not itself a credential, a secret
/// location, or a fact that materially helps an attacker choose a target.
/// **Deny-by-default is the MECHANISM; the operator's ruling is the OUTCOME,
/// and they are not in tension once the classification work is actually done.**
/// The ruling was "the full effective set of configuration settings, with
/// secrets masked". Shipping a one-entry list would have honoured the mechanism
/// and quietly failed the ruling -- an operator would see almost nothing. So
/// every field the schema defines today is classified here, deliberately, one
/// at a time; what deny-by-default still buys is that a field added TOMORROW is
/// masked until someone does the same for it.
///
/// None of these carry secret material. Maknae's secrets are not in
/// `maknae.yaml` at all -- they arrive via `$CREDENTIALS_DIRECTORY` and sealed
/// files under `private/`, which this view never reads.
const DISCLOSABLE: &[&str] = &[
    // Deployment identity. Already baked into every plane leaf's URI SAN, so
    // any peer completing a handshake has it; withholding it here would hide
    // it from the operator and from nobody else.
    "core.deployment_id",
    // The rest of `core`, per `docs/configuration.md` §4.
    //
    // THE AUTHORITY IS THE UNION, and getting that wrong is what produced two
    // separate misses. Reading only the parsers missed these: §4 says
    // `schema_version` and `identity.*` are "carried as-is" for their
    // consumers, so no parser in this crate names them. Then reading only
    // `docs/configuration.md` would miss twelve of the entries below --
    // it documents `core` (§4) and `lake` (§5) and nothing else, while
    // `boot.rs` registers `vault`, `transport`, `audit` and `principal` too,
    // and §6 still calls extension sections "not yet supported".
    //
    // So the surface to classify is: `docs/configuration.md` §4/§5, PLUS
    // `transport.rs`, `audit_cfg.rs`, `principal.rs` and
    // `maknae-vault/src/config.rs`, PLUS `boot.rs`'s SectionSpec list. The
    // `config-disclosure-drift` gate enumerates it so this comment is not the
    // control -- prose telling an author where to look has now been wrong
    // twice.
    // Same class of deployment-shape fact as `deployment_id`, and the
    // documented minimal config consists of little else -- masking them
    // reproduces "the operator sees almost nothing" on the shape the docs
    // actually tell operators to write.
    "core.schema_version",
    "core.identity.instance_id",
    "core.identity.name",
    "core.identity.domain",
    "core.identity.urn_root",
    // Vault WHERE and WHICH MOUNT -- never a credential. `vault_config_from_
    // document` accepts `vault.deployment_id` as a fallback spelling for the
    // `core` one, so it is classified identically; omitting it would make the
    // term's usefulness depend on which supported spelling a site chose.
    "vault.addr",
    "vault.approle_mount",
    "vault.pki_int_mount",
    "vault.deployment_id",
    // Audit destination. A path, and the operator already needs it to find the
    // log they are debugging.
    "audit.jsonl_path",
    // The enrolled principal.
    //
    // The reason is NOT "the operator is reading their own record" -- that was
    // the recorded rationale and it names the wrong audience. The reader is
    // whoever holds an `admin` binding, and `bindings:` maps any resolvable
    // local identity into that role, the reserved `agent` token included. So
    // the audience can be the untrusted agent runtime.
    //
    // Disclosed anyway, deliberately: a uid, a login name and a home path are
    // facts any local process can read from `/etc/passwd`. Withholding them
    // from a subject that can call `getpwuid` buys nothing. That argument is
    // about the FACTS, not about who is asking, which is why it survives the
    // audience being wrong.
    "principal.name",
    "principal.uid",
    "principal.home",
    // Transport shape, as resolved -- see `merge_resolved_defaults`.
    "transport.socket_path",
    "transport.max_connections",
    "transport.frame_max_bytes",
    "transport.handshake_timeout_ms",
    "transport.read_timeout_ms",
    // NOT classified, deliberately. Each carries its reason, because "absent
    // from the list" and "considered and withheld" are different states and
    // only one of them survives a review:
    //
    //   audit.au3_1 -- SUPPRESSED, not masked; see the list above. Masking was
    //     the first decision and it was wrong for the reason `MASK`'s doc now
    //     records: the sub-key NAMES are deployer-authored and a path allowlist
    //     cannot classify what it cannot enumerate.
    //
    //   audit.siem -- an offload ENDPOINT, not a path, with no schema, no
    //     validator, and today no consumer at all. The dominant real-world
    //     shapes for one embed a credential IN the URL: `?token=...`,
    //     `user:pass@host`, or a path segment that IS the secret.
    //     `audit_from_section` rejects none of those. A field whose format is
    //     undecided is exactly the case deny-by-default exists for. Reclassify
    //     when the offload path lands and the format is pinned.
    //
    //   core.handling.* -- classification, sci, releasable_to, cui_permitted,
    //     cui_categories_permitted, dissemination_permitted, accreditation_ref
    //     (see `ceiling.rs`). A deployment's classification CEILING. An
    //     operator debugging a Gated ingest wants it; it is also the single
    //     fact that most helps an attacker choose a target, and on a DoD
    //     deployment the ceiling is frequently itself classified. Deny-by-
    //     default breaks the tie: masked until the operator rules otherwise.
    //
    //   lake -- a registered section (`boot.rs`) whose schema is the Knowledge
    //     Lake's, not Maknae's, and which no parser in this crate reads. It
    //     masks by default; named here so its absence from the allowlist is a
    //     recorded decision rather than an oversight, and so ADR-0010's claim
    //     that the reasons live beside this list is true of it too.
    //
    //   every future field, in every future section.
];

/// Paths whose **KEY ITSELF** must not be disclosed — omitted from the view
/// entirely, not masked.
///
/// The failure that motivated it: [`MASK`] was documented as universally benign
/// ("says THAT the setting is configured, never what it is"), and for a VALUE it
/// is. For a KEY it is not. `sudo maknae enroll --insecure-plaintext-secret`
/// writes `vault.insecure_plaintext_secret_path` into `maknae.yaml`; masking its
/// value while showing its key discloses that **this host holds an AppRole
/// SecretID in plaintext on disk** — exactly the "secret location, or a fact
/// that materially helps an attacker choose a target" that [`DISCLOSABLE`]'s own
/// bar forbids. Values had a classifier; key names had none.
///
/// Suppression beats disclosure: a path here is omitted even if a later edit
/// also lists it on [`DISCLOSABLE`].
const SUPPRESSED: &[&str] = &[
    // Its PRESENCE is the finding. Absent on a correctly-enrolled host, so its
    // absence from the view is not itself a signal.
    "vault.insecure_plaintext_secret_path",
    // The deployer's AU-3(1) extension object, and everything under it.
    //
    // Masking was the recorded decision and it applied the VALUE rule to a KEY
    // problem -- the same confusion `MASK`'s own corrected doc warns about. The
    // paths under `au3_1` are deployer-authored strings with NO schema
    // (`audit_cfg::to_json` accepts an arbitrary map), so a code-declared path
    // allowlist is structurally incapable of classifying them: "unclassified
    // therefore withheld" silently degrades to "unclassified therefore the key
    // name ships" for exactly this subtree. `audit: { au3_1: { enclave:
    // "SCIF-B7" } }` put `au3_1.enclave` on the wire. Prefix-suppressed.
    "audit.au3_1",
    // The classification ceiling, and everything under it (prefix match).
    //
    // Masking these was not enough, and the reason is the same one that earned
    // this list its first entry. `ceiling_from_core` returns the PUBLIC
    // baseline when `handling` is absent and only parses a ceiling when it is
    // present; neither the shipped skeleton nor `maknae enroll` writes one. So
    // `core.handling.ceiling.classification: <value set>` in the view says,
    // unambiguously: *this deployment has an explicitly configured,
    // above-baseline ceiling*. That is a presence signal, on the field this
    // module's own comments call the single fact that most helps an attacker
    // choose a target and which is frequently itself classified.
    //
    // The asymmetry is the point: for a VALUE, deny-by-default masking is
    // enough. For a field whose mere EXISTENCE is the disclosure, it is not.
    "core.handling",
];

#[derive(PartialEq, Debug)]
enum Disclosure {
    /// Show the value.
    Clear,
    /// Show the key, mask the value.
    Mask,
    /// Show neither — the key's existence is itself the disclosure.
    Omit,
}

/// ONE classifier, used by the file walk and by [`Document::merge_resolved`],
/// so the two cannot drift. `maknae-proto`'s `ConfigView` doc names the hazard
/// of a second redaction implementation; it applies inside this crate too.
fn classify(section: &str, path: &str, disclosable: &[&str]) -> Disclosure {
    let full = format!("{section}.{path}");
    // PREFIX match, not exact. `core.handling` has seven leaves; listing them
    // one by one means the eighth, added later, is disclosed by default --
    // which is the denylist failure this whole module rejects, reintroduced
    // inside the suppression list itself.
    if SUPPRESSED
        .iter()
        .any(|p| full == *p || full.starts_with(&format!("{p}.")))
    {
        return Disclosure::Omit;
    }
    if disclosable.contains(&full.as_str()) {
        return Disclosure::Clear;
    }
    Disclosure::Mask
}

/// `disclosable` is a PARAMETER rather than a direct read of [`DISCLOSABLE`],
/// so the rule can be exercised against every `Value` shape without widening
/// the real allowlist to make a type reachable. Both production call sites --
/// [`Document::disclosable_view`] and [`Document::merge_resolved`] -- pass
/// [`DISCLOSABLE`]. ([`SUPPRESSED`] is NOT parameterised: `classify` reads it
/// directly, so suppression cannot be relaxed by a caller.)
fn flatten(
    disclosable: &[&str],
    section: &str,
    prefix: &str,
    v: &Value,
    out: &mut BTreeMap<String, String>,
) {
    match v {
        Value::Map(entries) => {
            for (k, sub) in entries {
                let next = if prefix.is_empty() {
                    k.clone()
                } else {
                    format!("{prefix}.{k}")
                };
                flatten(disclosable, section, &next, sub, out);
            }
        }
        _ => {
            if prefix.is_empty() {
                // A section whose whole body is a scalar: name it by section.
                // NOTE the CLASSIFIER path is `<section>.<section>` (doubled),
                // not `<section>`. An author disclosing such a section must
                // write `"lonely.lonely"`; a bare `"lonely"` on DISCLOSABLE
                // matches nothing and the field silently masks. (Suppression is
                // unaffected -- the prefix rule makes a bare section name work,
                // which is the safe direction.)
                if classify(section, section, disclosable) == Disclosure::Omit {
                    return;
                }
                out.insert(
                    section.to_string(),
                    render(disclosable, section, section, v),
                );
                return;
            }
            if classify(section, prefix, disclosable) == Disclosure::Omit {
                return;
            }
            out.insert(prefix.to_string(), render(disclosable, section, prefix, v));
        }
    }
}

fn render(disclosable: &[&str], section: &str, path: &str, v: &Value) -> String {
    // Absence is reported before disclosure is even considered: a key with no
    // value has nothing to leak, and the operator needs to see it is unset.
    if matches!(v, Value::Null) {
        return NOT_SET.to_string();
    }
    if classify(section, path, disclosable) != Disclosure::Clear {
        return MASK.to_string();
    }
    match v {
        Value::Bool(b) => b.to_string(),
        Value::Int(n) => n.to_string(),
        Value::Float(f) => f.to_string(),
        Value::Str(s) => s.clone(),
        // A declared field holding a SEQUENCE is not rendered element-wise:
        // the declaration was made about a scalar, and silently widening it to
        // a list would disclose values nobody classified.
        //
        // `Value::Map` never arrives here -- `flatten` recurses into maps and
        // only calls `render` from its non-map arm. So a MAP-VALUED entry on
        // [`DISCLOSABLE`] (`"vault.approle"`) matches NOTHING: it is a silent
        // no-op, not a mask, because each leaf below it is classified on its
        // own full path. Declare the leaves, never the branch.
        Value::Seq(_) | Value::Null => MASK.to_string(),
        Value::Map(_) => unreachable!("flatten recurses into maps; render sees leaves only"),
    }
}

/// Everything the daemon RESOLVED that the file may not have stated. Passed as
/// primitives so this crate keeps no dependency on `maknae-vault`.
pub struct ResolvedSettings<'a> {
    pub transport: &'a crate::TransportConfig,
    pub audit: &'a crate::AuditConfig,
    /// `None` means "resolved to nothing" and renders [`NOT_SET`]. It does NOT
    /// mean "the vault config failed to resolve" — `vault_config_from_document`
    /// defaults both mounts, and the caller has already `?`'d it before this
    /// point, so an unresolvable config never reaches here. Passing `None` for
    /// a field the daemon is actually defaulting would report `<not set>` for a
    /// mount in active use, which is the MASK/NOT_SET conflation inverted.
    pub vault_approle_mount: Option<String>,
    pub vault_pki_int_mount: Option<String>,
}

/// The complete `admin.config.show` view: the file walk, plus every resolved
/// default folded in under the same classification.
///
/// **Extracted from the daemon's boot path deliberately.** It lived inline in
/// `maknae-kernel::run`, which is T3 and mutation-excluded, so the decision of
/// *which fields to fold and what to present for an absent one* had no test and
/// no mutation coverage — and a defect there (an unset `audit.siem` reported as
/// `<value set>`) shipped through two review rounds unseen. That is a
/// disclosure decision, so it belongs in a gated crate, next to the rule it
/// composes with.
pub fn effective_view(
    doc: &Document,
    r: &ResolvedSettings<'_>,
) -> BTreeMap<String, BTreeMap<String, String>> {
    let mut v = doc.disclosable_view();
    Document::merge_resolved(
        &mut v,
        "audit",
        &[
            ("jsonl_path", Some(r.audit.jsonl_path.display().to_string())),
            // `None` when unset -- NOT a sentinel string. `siem` is withheld,
            // so a masked rendering here would claim an external offload
            // endpoint exists on every deployment that has none.
            ("siem", r.audit.siem.clone()),
        ],
    );
    Document::merge_resolved(
        &mut v,
        "vault",
        &[
            ("approle_mount", r.vault_approle_mount.clone()),
            ("pki_int_mount", r.vault_pki_int_mount.clone()),
        ],
    );
    Document::merge_resolved(
        &mut v,
        "transport",
        &[
            (
                "socket_path",
                Some(r.transport.socket_path.display().to_string()),
            ),
            (
                "max_connections",
                Some(r.transport.max_connections.to_string()),
            ),
            (
                "frame_max_bytes",
                Some(r.transport.frame_max_bytes.to_string()),
            ),
            (
                "handshake_timeout_ms",
                Some(r.transport.handshake_timeout_ms.to_string()),
            ),
            (
                "read_timeout_ms",
                Some(r.transport.read_timeout_ms.to_string()),
            ),
        ],
    );
    v
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Value;

    #[test]
    fn section_lookup_and_overrides() {
        let doc = Document::new(
            vec![
                ("core".into(), Value::Int(1), Source::Base),
                (
                    "authz".into(),
                    Value::Int(2),
                    Source::ConfigD("cfg.yaml".into()),
                ),
            ],
            vec![Override {
                section: "authz".into(),
                winner: Source::ConfigD("cfg.yaml".into()),
                shadowed: Source::Base,
            }],
        );
        assert_eq!(doc.section("core"), Some(&Value::Int(1)));
        assert_eq!(doc.section("authz"), Some(&Value::Int(2)));
        assert_eq!(doc.section("missing"), None);
        assert_eq!(doc.overrides().len(), 1);
        assert_eq!(doc.overrides()[0].section, "authz");
    }

    // ---- `admin.config.show` disclosure rule (#162 Phase 2) ----

    fn doc(sections: Vec<(&str, Value)>) -> Document {
        Document::new(
            sections
                .into_iter()
                .map(|(n, v)| (n.to_string(), v, Source::Base))
                .collect(),
            Vec::new(),
        )
    }

    fn map(pairs: Vec<(&str, Value)>) -> Value {
        Value::Map(pairs.into_iter().map(|(k, v)| (k.to_string(), v)).collect())
    }

    /// The SHAPE is disclosed in full: every section, every key, at every depth.
    /// That is what makes the term worth having -- an operator debugging a
    /// deployment needs to see which settings exist and which are set.
    #[test]
    fn every_key_at_every_depth_appears_in_the_view() {
        let d = doc(vec![
            (
                "core",
                map(vec![("deployment_id", Value::Str("site-7".into()))]),
            ),
            (
                "vault",
                map(vec![
                    ("addr", Value::Str("https://v:8200".into())),
                    ("nested", map(vec![("deep", Value::Int(1))])),
                ]),
            ),
        ]);
        let v = d.disclosable_view();
        assert!(v.contains_key("core"), "{v:?}");
        assert!(v.contains_key("vault"), "{v:?}");
        let vault = v.get("vault").expect("vault section");
        assert!(vault.contains_key("addr"), "{vault:?}");
        assert!(
            vault.contains_key("nested.deep"),
            "nesting must be walked: {vault:?}"
        );
    }

    /// A field NOT on the disclosable list shows a presence marker, never its
    /// value. `<value set>` says THAT it is configured, which is what an
    /// operator debugging an unset credential needs; the value never is.
    #[test]
    fn an_undeclared_field_is_masked_to_a_presence_marker() {
        let d = doc(vec![(
            "vault",
            map(vec![(
                "root_token",
                Value::Str("hvs.CAESIJ-real-secret".into()),
            )]),
        )]);
        let v = d.disclosable_view();
        let got = v["vault"]["root_token"].clone();
        assert_eq!(got, MASK, "an undeclared field must not disclose its value");
        assert!(
            !format!("{v:?}").contains("hvs.CAESIJ"),
            "the secret must not appear ANYWHERE in the view: {v:?}"
        );
    }

    /// DENY BY DEFAULT is the whole design, and this is the test that holds it.
    ///
    /// A brand-new config field -- one nobody has classified, because it was
    /// added five minutes ago -- is masked. The alternative, a denylist of
    /// known-sensitive names, defaults every future field to DISCLOSED and
    /// depends on whoever adds it remembering to classify it. A rule that
    /// depends on someone remembering is not a control.
    #[test]
    fn a_field_nobody_has_classified_yet_is_masked() {
        let d = doc(vec![(
            "some_future_section",
            map(vec![
                ("a_field_invented_today", Value::Str("sensitive?".into())),
                ("innocuous_looking_count", Value::Int(42)),
            ]),
        )]);
        let v = d.disclosable_view();
        assert_eq!(v["some_future_section"]["a_field_invented_today"], MASK);
        assert_eq!(
            v["some_future_section"]["innocuous_looking_count"], MASK,
            "even an int in an unknown section is masked -- the classifier is the \
                 PATH, not the type, and 'it looks harmless' is not a control"
        );
    }

    /// A field ON the list shows its real value. Without this the masking
    /// would be indistinguishable from masking everything, and the term would
    /// disclose nothing useful.
    #[test]
    fn a_declared_field_discloses_its_value() {
        let d = doc(vec![(
            "core",
            map(vec![("deployment_id", Value::Str("site-7".into()))]),
        )]);
        assert_eq!(d.disclosable_view()["core"]["deployment_id"], "site-7");
    }

    /// An ABSENT field is distinguishable from a masked one. "not set" and
    /// "set to something I will not show you" are different answers to the
    /// operator's actual question, and collapsing them makes the term useless
    /// for the case it exists to serve.
    #[test]
    fn absent_is_distinguishable_from_masked() {
        let d = doc(vec![("vault", map(vec![("addr", Value::Null)]))]);
        let v = d.disclosable_view();
        assert_eq!(v["vault"]["addr"], NOT_SET);
    }
    /// Every `Value` shape, against a test allowlist. The real [`DISCLOSABLE`]
    /// holds one string field, so these arms are otherwise unreachable -- and
    /// widening the real list to make them reachable would disclose fields
    /// nobody argued for, which is the opposite of the point.
    #[test]
    fn a_declared_field_renders_every_scalar_type_and_masks_every_collection() {
        let allow: &[&str] = &["s.b", "s.i", "s.f", "s.t", "s.seq", "s.null"];
        let mut out = BTreeMap::new();
        flatten(
            allow,
            "s",
            "",
            &map(vec![
                ("b", Value::Bool(true)),
                ("i", Value::Int(-7)),
                ("f", Value::Float(1.5)),
                ("t", Value::Str("plain".into())),
                ("seq", Value::Seq(vec![Value::Str("hidden".into())])),
                ("null", Value::Null),
            ]),
            &mut out,
        );
        assert_eq!(out["b"], "true");
        assert_eq!(out["i"], "-7");
        assert_eq!(out["f"], "1.5");
        assert_eq!(out["t"], "plain");
        // DECLARED but a collection: still masked. The declaration was made
        // about a scalar, and widening it silently would disclose elements
        // nobody classified -- `hidden` must not appear.
        assert_eq!(out["seq"], MASK);
        assert!(!format!("{out:?}").contains("hidden"), "{out:?}");
        assert_eq!(out["null"], NOT_SET);
    }

    /// `merge_resolved` applies the SAME classification as the file path. A
    /// resolved default is not privileged for having come from code -- an
    /// unclassified one masks exactly as an unclassified file value does.
    #[test]
    fn resolved_defaults_are_classified_like_everything_else() {
        let mut view: BTreeMap<String, BTreeMap<String, String>> = BTreeMap::new();
        Document::merge_resolved(
            &mut view,
            "transport",
            &[
                ("socket_path", Some("/run/maknae/maknaed.sock".to_string())),
                ("a_future_transport_field", Some("unclassified".to_string())),
            ],
        );
        assert_eq!(view["transport"]["socket_path"], "/run/maknae/maknaed.sock");
        assert_eq!(
            view["transport"]["a_future_transport_field"], MASK,
            "coming from code rather than the file earns no disclosure"
        );
    }

    /// A key whose EXISTENCE is the disclosure is omitted, not masked.
    ///
    /// `vault.insecure_plaintext_secret_path` appears only on a host enrolled
    /// with `--insecure-plaintext-secret`. Masking its value while showing its
    /// key would still tell a reader this host keeps an AppRole SecretID in
    /// plaintext on disk -- a secret LOCATION, which the allowlist's own bar
    /// forbids disclosing.
    #[test]
    fn a_suppressed_key_is_omitted_entirely_not_masked() {
        let d = doc(vec![(
            "vault",
            map(vec![
                ("addr", Value::Str("https://v:8200".into())),
                (
                    "insecure_plaintext_secret_path",
                    Value::Str("/etc/maknaed/secret-id".into()),
                ),
            ]),
        )]);
        let v = d.disclosable_view();
        assert!(
            !v["vault"].contains_key("insecure_plaintext_secret_path"),
            "the KEY must not appear at all, masked or otherwise: {v:?}"
        );
        assert!(
            !format!("{v:?}").contains("secret-id"),
            "and certainly not its value: {v:?}"
        );
        // The rest of the section is unaffected -- suppression is per-path.
        assert!(v["vault"].contains_key("addr"), "{v:?}");
    }

    /// Suppression beats disclosure, so a later edit that lists a suppressed
    /// path on the allowlist cannot re-open it by accident.
    #[test]
    fn suppression_wins_over_an_allowlist_entry_for_the_same_path() {
        let allow: &[&str] = &["vault.insecure_plaintext_secret_path"];
        let mut out = BTreeMap::new();
        flatten(
            allow,
            "vault",
            "",
            &map(vec![(
                "insecure_plaintext_secret_path",
                Value::Str("/etc/maknaed/secret-id".into()),
            )]),
            &mut out,
        );
        assert!(
            out.is_empty(),
            "allowlisting must not defeat suppression: {out:?}"
        );
    }

    /// `audit.siem` and the classification ceiling are withheld. Pinned so that
    /// re-adding either is a red test and a conversation, not a quiet edit.
    #[test]
    fn deliberately_withheld_fields_stay_withheld() {
        let d = doc(vec![
            (
                "audit",
                map(vec![(
                    "siem",
                    Value::Str("https://splunk:8088/collector?token=SECRET".into()),
                )]),
            ),
            (
                "core",
                map(vec![(
                    "handling",
                    map(vec![(
                        "ceiling",
                        map(vec![("classification", Value::Str("SECRET".into()))]),
                    )]),
                )]),
            ),
        ]);
        let v = d.disclosable_view();
        assert_eq!(
            v["audit"]["siem"], MASK,
            "an endpoint may carry a credential"
        );
        assert!(!format!("{v:?}").contains("token=SECRET"), "{v:?}");
        // A withheld PRESENCE SIGNAL is omitted outright, which is strictly
        // stronger than masking. `handling` is absent unless a deployment
        // configured an above-baseline ceiling, so the key appearing at all --
        // even masked -- is the finding.
        assert!(
            !v.contains_key("core"),
            "an all-suppressed section must not appear AT ALL -- an empty `core: {{}}` \
             is itself the signal that a ceiling is configured: {v:?}"
        );
        assert!(!format!("{v:?}").contains("SECRET"), "{v:?}");
    }

    /// THE REGRESSION TEST. An unset `audit.siem` must read `<not set>`, never
    /// `<value set>`.
    ///
    /// The shipped skeleton sets no `siem`. The first fold took a bare `String`,
    /// so the caller invented a sentinel and the `Mask` arm discarded it and
    /// inserted `MASK` -- telling every operator, on every deployment, that an
    /// external audit-offload endpoint was configured when none was. On the one
    /// field the same review flagged as credential-bearing. It survived two
    /// review rounds because the fold lived in a T3, mutation-excluded file
    /// with no test; it lives here now for exactly that reason.
    #[test]
    fn an_unset_resolved_field_reads_not_set_not_masked() {
        let doc = Document::new(
            vec![(
                "audit".to_string(),
                map(vec![(
                    "jsonl_path",
                    Value::Str("/var/log/maknae/audit.jsonl".into()),
                )]),
                Source::Base,
            )],
            Vec::new(),
        );
        let transport = crate::TransportConfig::default();
        let audit = crate::AuditConfig {
            jsonl_path: "/var/log/maknae/audit.jsonl".into(),
            siem: None, // the shipped skeleton
            au3_1: serde_json::json!({}),
        };
        let v = effective_view(
            &doc,
            &ResolvedSettings {
                transport: &transport,
                audit: &audit,
                vault_approle_mount: None,
                vault_pki_int_mount: None,
            },
        );
        assert_eq!(
            v["audit"]["siem"], NOT_SET,
            "an unset offload endpoint must not read as configured (and NOT_SET \
             is a distinct constant from MASK, so this pins the distinction)"
        );
        // A SET one is still withheld -- absence handling must not become a
        // disclosure route for the value.
        let audit_set = crate::AuditConfig {
            siem: Some("https://splunk:8088?token=SECRET".into()),
            ..audit
        };
        let v2 = effective_view(
            &doc,
            &ResolvedSettings {
                transport: &transport,
                audit: &audit_set,
                vault_approle_mount: None,
                vault_pki_int_mount: None,
            },
        );
        assert_eq!(v2["audit"]["siem"], MASK);
        assert!(!format!("{v2:?}").contains("token=SECRET"), "{v2:?}");
    }

    /// Resolved defaults the FILE never stated still appear -- the reason the
    /// fold exists. All three sections, not just the one a review named.
    #[test]
    fn every_section_with_resolved_defaults_is_folded() {
        let doc = Document::new(Vec::new(), Vec::new()); // an empty file
        let transport = crate::TransportConfig::default();
        let audit = crate::AuditConfig {
            jsonl_path: "/var/log/maknae/audit.jsonl".into(),
            siem: None,
            au3_1: serde_json::json!({}),
        };
        let v = effective_view(
            &doc,
            &ResolvedSettings {
                transport: &transport,
                audit: &audit,
                vault_approle_mount: Some("maknae-approle".into()),
                vault_pki_int_mount: Some("maknae-pki-int".into()),
            },
        );
        assert_eq!(v["transport"]["frame_max_bytes"], "65536");
        assert_eq!(v["audit"]["jsonl_path"], "/var/log/maknae/audit.jsonl");
        assert_eq!(v["vault"]["approle_mount"], "maknae-approle");
        assert_eq!(v["vault"]["pki_int_mount"], "maknae-pki-int");
    }

    /// A suppressed path stays suppressed on the RESOLVED lane too. Without
    /// this, `merge_resolved`'s `Omit` arm is the one insertion site of three
    /// that suppression reaches only in theory.
    #[test]
    fn merge_resolved_omits_a_suppressed_path() {
        let mut v: BTreeMap<String, BTreeMap<String, String>> = BTreeMap::new();
        Document::merge_resolved(
            &mut v,
            "vault",
            &[
                ("addr", Some("https://v:8200".into())),
                (
                    "insecure_plaintext_secret_path",
                    Some("/etc/maknaed/secret-id".into()),
                ),
            ],
        );
        assert!(v["vault"].contains_key("addr"));
        assert!(
            !v["vault"].contains_key("insecure_plaintext_secret_path"),
            "suppression must hold on the resolved lane too: {v:?}"
        );
    }

    /// Folding a SUPPRESSED path with `None` must still omit it. The absence
    /// path is a second insertion site inside `merge_resolved`, and an earlier
    /// ordering checked absence first -- which would have emitted the
    /// suppressed KEY as `<not set>` on every host that does NOT have the
    /// plaintext secret, and omitted it on every host that does. Round 2's leak
    /// with the polarity inverted: the posture disclosed by absence.
    #[test]
    fn merge_resolved_omits_a_suppressed_path_even_when_it_resolves_to_nothing() {
        let mut v: BTreeMap<String, BTreeMap<String, String>> = BTreeMap::new();
        Document::merge_resolved(
            &mut v,
            "vault",
            &[
                ("addr", Some("https://v:8200".into())),
                ("insecure_plaintext_secret_path", None),
            ],
        );
        assert!(
            !v["vault"].contains_key("insecure_plaintext_secret_path"),
            "a suppressed path must be omitted whether it resolves to a value or \
             to nothing -- otherwise its ABSENCE becomes the disclosure: {v:?}"
        );
        assert!(v["vault"].contains_key("addr"), "{v:?}");
    }

    /// The prefix rule must not OVER-match a sibling. `core.handling_notes`
    /// shares a prefix with `core.handling` as a string but is a different
    /// field, and suppressing it would be silent over-withholding.
    #[test]
    fn the_prefix_rule_does_not_swallow_a_sibling_key() {
        let d = doc(vec![(
            "core",
            map(vec![("handling_notes", Value::Str("free text".into()))]),
        )]);
        let v = d.disclosable_view();
        assert_eq!(
            v["core"]["handling_notes"], MASK,
            "a sibling of a suppressed prefix is masked, not omitted: {v:?}"
        );
    }

    /// Suppression is a PREFIX rule, so a leaf added under `core.handling`
    /// later is suppressed without anyone remembering to list it.
    #[test]
    fn suppression_covers_every_leaf_under_a_suppressed_prefix() {
        let d = doc(vec![(
            "core",
            map(vec![(
                "handling",
                map(vec![
                    ("accreditation_ref", Value::Str("ATO-123".into())),
                    (
                        "ceiling",
                        map(vec![
                            ("classification", Value::Str("SECRET".into())),
                            ("a_leaf_invented_later", Value::Str("x".into())),
                        ]),
                    ),
                ]),
            )]),
        )]);
        let v = d.disclosable_view();
        assert!(
            !v.contains_key("core"),
            "the whole handling subtree must be omitted, including leaves nobody listed: {v:?}"
        );
        assert!(!format!("{v:?}").contains("ATO-123"), "{v:?}");
    }

    /// A MAP-valued entry on the allowlist matches nothing -- it is a silent
    /// no-op, and the leaves below it are classified on their own full paths.
    /// Pinned because the natural reading of "declared fields are disclosed"
    /// is that declaring a branch discloses the branch, and it does not.
    #[test]
    fn a_map_valued_allowlist_entry_discloses_nothing() {
        let allow: &[&str] = &["s.approle"]; // the BRANCH, not its leaves
        let mut out = BTreeMap::new();
        flatten(
            allow,
            "s",
            "",
            &map(vec![(
                "approle",
                map(vec![("role_id", Value::Str("leak-me".into()))]),
            )]),
            &mut out,
        );
        assert_eq!(
            out["approle.role_id"], MASK,
            "declaring the branch must not disclose the leaf"
        );
        assert!(!format!("{out:?}").contains("leak-me"), "{out:?}");
    }

    /// A section whose entire body is a scalar is keyed by the section name,
    /// not dropped. Without this arm such a section would vanish from the
    /// view -- an operator would see no evidence the setting exists.
    #[test]
    fn a_scalar_section_is_keyed_by_its_section_name() {
        let d = doc(vec![("lonely", Value::Str("value".into()))]);
        let v = d.disclosable_view();
        assert_eq!(v["lonely"]["lonely"], MASK, "present, and masked: {v:?}");
    }

    /// The allowlist is matched on the FULL `section.path`, so the same leaf
    /// name in a different section is not disclosed by accident.
    #[test]
    fn the_allowlist_matches_the_full_path_not_the_leaf_name() {
        let allow: &[&str] = &["core.deployment_id"];
        let mut out = BTreeMap::new();
        flatten(
            allow,
            "vault",
            "",
            &map(vec![("deployment_id", Value::Str("leak".into()))]),
            &mut out,
        );
        assert_eq!(
            out["deployment_id"], MASK,
            "leaf-name collision must not disclose"
        );
    }
}
