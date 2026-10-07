use crate::decide::{class_of, Class};
use maknae_graph::kernel::{persisted_compiled_set, CLASS, TERM};
use maknae_graph::record::{AttrValue, Attrs};
use maknae_graph::schema::{CompiledNode, CompiledSet};

#[rustfmt::skip]
pub const ACTION_TERMS: [&str; 57] = [
    "liveness.ping",
    "admin.whoami", "admin.status", "admin.config.show", "admin.audit.tail", "admin.policy.reload",
    "admin.subject.list", "admin.subject.bind", "admin.subject.unbind", "admin.contain", "admin.release",
    "admin.credential.rotate", "admin.provider.list", "admin.provider.set", "admin.provider.disable",
    "admin.credential.broker", "admin.session.list", "admin.session.terminate",
    "session.new", "session.resume", "session.close", "session.delete", "session.list", "session.fork",
    "session.prompt", "session.cancel", "session.set_config_option", "session.set_mode", "session.load",
    "session.update", "session.request_permission", "session.elicit.create", "session.elicit.complete",
    "session.compact",
    "fs.read", "fs.write", "fs.delete", "fs.move", "fs.list", "fs.stat", "fs.mkdir", "fs.link", "fs.chmod", "fs.chown",
    "terminal.create", "terminal.output", "terminal.wait_for_exit", "terminal.kill", "terminal.release", "terminal.input",
    "mcp.connect", "mcp.disconnect", "mcp.message", "mcp.tool.call", "mcp.resource.read", "mcp.prompt.get", "mcp.sampling.create",
];
pub const KERNEL_TERMS: [&str; 2] = ["kernel.contain", "kernel.session.terminate"];
pub const CLASSES: [&str; 7] = [
    "liveness", "admin", "session", "fs", "terminal", "mcp", "kernel",
];
const ATTR_CLASS: &str = "class";

pub fn class_name(term: &str) -> Option<&'static str> {
    Some(match class_of(term)? {
        Class::Liveness => "liveness",
        Class::Admin => "admin",
        Class::Session => "session",
        Class::Fs => "fs",
        Class::Terminal => "terminal",
        Class::Mcp => "mcp",
        Class::Kernel => "kernel",
    })
}

/// The full in-memory compiled set: the persisted roles, then every term, then every class.
pub fn compiled_set(label: &str) -> CompiledSet {
    let mut nodes: Vec<CompiledNode> = persisted_compiled_set(label).iter().cloned().collect();
    for t in ACTION_TERMS.iter().chain(KERNEL_TERMS.iter()) {
        let mut attrs = Attrs::new();
        attrs.insert(
            ATTR_CLASS.into(),
            AttrValue::Str(class_name(t).expect("every term has a class").into()),
        );
        nodes.push(CompiledNode {
            kind: TERM,
            key: (*t).into(),
            label: label.into(),
            attrs,
        });
    }
    for c in CLASSES {
        nodes.push(CompiledNode {
            kind: CLASS,
            key: c.into(),
            label: label.into(),
            attrs: Attrs::new(),
        });
    }
    CompiledSet::new(nodes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use maknae_graph::schema::CompiledSet;

    #[test]
    fn every_term_in_the_manifest_is_enumerated_and_nothing_else() {
        let manifest = include_str!("../../../ci/gates/verb-manifest.txt");
        let mut expected: Vec<(&str, &str)> = manifest
            .lines()
            .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
            .filter_map(|l| {
                let mut f = l.split('\t');
                match (f.next(), f.next()) {
                    (Some(k @ ("action" | "kernel-action")), Some(name)) => Some((k, name)),
                    _ => None,
                }
            })
            .collect();
        expected.sort();
        let mut got: Vec<(&str, &str)> = ACTION_TERMS
            .iter()
            .map(|t| ("action", *t))
            .chain(KERNEL_TERMS.iter().map(|t| ("kernel-action", *t)))
            .collect();
        got.sort();
        assert_eq!(
            got, expected,
            "the vocabulary must equal the manifest exactly (both directions)"
        );
    }

    #[test]
    fn every_term_has_a_class_and_the_grantable_terms_are_terms() {
        for t in ACTION_TERMS.iter().chain(KERNEL_TERMS.iter()) {
            let c = class_name(t).unwrap_or_else(|| panic!("{t} has no class"));
            assert!(CLASSES.contains(&c));
        }
        for g in crate::grantable_actions() {
            assert!(ACTION_TERMS.contains(g));
        }
        assert_eq!(class_name("liveness_bypass.exec"), None);
    }

    #[test]
    fn class_name_names_each_class_by_its_own_prefix() {
        for c in CLASSES {
            assert_eq!(class_name(c), Some(c));
        }
    }

    #[test]
    fn the_compiled_set_is_roles_then_terms_then_classes_with_member_class_attrs() {
        let set = compiled_set("UNCLASSIFIED");
        let roles: Vec<&str> = set
            .iter()
            .filter(|c| c.kind == maknae_graph::kernel::ROLE)
            .map(|c| c.key.as_str())
            .collect();
        assert_eq!(roles, maknae_graph::kernel::ROLES);
        assert_eq!(
            set.iter()
                .filter(|c| c.kind == maknae_graph::kernel::TERM)
                .count(),
            59
        );
        assert_eq!(
            set.iter()
                .filter(|c| c.kind == maknae_graph::kernel::CLASS)
                .count(),
            7
        );
        let t = set.get(maknae_graph::kernel::TERM, "fs.read").unwrap();
        assert_eq!(
            t.attrs.get("class"),
            Some(&maknae_graph::record::AttrValue::Str("fs".into()))
        );
        assert_eq!(t.label, "UNCLASSIFIED");
        let k = set
            .get(maknae_graph::kernel::TERM, "kernel.contain")
            .unwrap();
        assert_eq!(
            k.attrs.get("class"),
            Some(&maknae_graph::record::AttrValue::Str("kernel".into()))
        );
        let c = set.get(maknae_graph::kernel::CLASS, "mcp").unwrap();
        assert_eq!(c.label, "UNCLASSIFIED");
        assert!(c.attrs.is_empty());
        let persisted = maknae_graph::kernel::persisted_compiled_set("UNCLASSIFIED");
        let ours = CompiledSet::new(
            set.iter()
                .filter(|c| c.kind == maknae_graph::kernel::ROLE)
                .cloned()
                .collect(),
        );
        assert_eq!(ours.canonical_bytes(), persisted.canonical_bytes());
        assert!(set.canonical_bytes().is_ok());
    }

    #[test]
    fn role_keys_agree_with_role_rs() {
        for r in maknae_graph::kernel::ROLES {
            assert_eq!(crate::role::Role::from_key(r).unwrap().key(), r);
        }
    }
}
