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
            out.insert(name.clone(), flat);
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
        fields: &[(&str, String)],
    ) {
        let entry = view.entry(section.to_string()).or_default();
        for (path, value) in fields {
            // The SAME classifier the file walk uses — a resolved default is
            // not privileged for having come from code.
            match classify(section, path, DISCLOSABLE) {
                Disclosure::Omit => continue,
                Disclosure::Clear => entry.insert((*path).to_string(), value.clone()),
                Disclosure::Mask => entry.insert((*path).to_string(), MASK.to_string()),
            };
        }
    }
}

/// Rendered in place of a value this crate has not declared disclosable. Says
/// THAT the setting is configured, never what it is -- presence is what an
/// operator debugging an unset credential needs; the value never is.
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
    // The enrolled principal. The operator IS this principal; hiding their own
    // uid and home from them serves nobody.
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
    //   audit.au3_1 -- operator-authored free-form JSON. Whatever a deployer
    //     put there has been reviewed by nobody, so it masks.
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
    //   every future field, in every future section.
];

/// `disclosable` is a PARAMETER, not a direct read of [`DISCLOSABLE`], so the
/// rule can be exercised against every `Value` shape without widening the real
/// allowlist to make types reachable. Production has exactly one caller and it
/// passes [`DISCLOSABLE`].
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
    if SUPPRESSED.contains(&full.as_str()) {
        return Disclosure::Omit;
    }
    if disclosable.contains(&full.as_str()) {
        return Disclosure::Clear;
    }
    Disclosure::Mask
}

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
        assert_ne!(v["vault"]["addr"], MASK);
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
                ("socket_path", "/run/maknae/maknaed.sock".to_string()),
                ("a_future_transport_field", "unclassified".to_string()),
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
        assert_eq!(
            v["core"]["handling.ceiling.classification"], MASK,
            "a deployment's classification ceiling is not disclosed by default"
        );
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
