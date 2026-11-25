use maknae_config::{CommandForm, Grammar, GrammarSet, ToolsCatalog, VENDOR_TOOLS_DIR};
use std::collections::BTreeMap;
use yaml_rust2::yaml::Hash;
use yaml_rust2::{Yaml, YamlEmitter, YamlLoader};

pub(crate) struct Dropin {
    pub entry: String,
    pub text: String,
    pub grants: Vec<String>,
    pub apps: Vec<(String, String)>,
}

fn key(name: &str) -> Yaml {
    Yaml::String(name.to_string())
}

fn mapping<'a>(doc: &'a Hash, name: &str) -> Result<&'a Hash, String> {
    doc.get(&key(name))
        .and_then(Yaml::as_hash)
        .ok_or_else(|| format!("the template has no `{name}` mapping"))
}

fn class_of<'a>(body: &'a Hash, classes: &Hash) -> Option<&'a str> {
    body.get(&key("credential"))
        .and_then(Yaml::as_str)
        .filter(|class| classes.contains_key(&key(class)))
}

fn narrow(entry: &mut Hash, name: &str, program: &str, want: &[String]) -> Result<(), String> {
    let no_command = || format!("entry `{name}` has no `{program}` grammar command to narrow");
    let Some(Yaml::Hash(commands)) = entry.get_mut(&key("commands")) else {
        return Err(no_command());
    };
    let mut narrowed = false;
    for (_, command) in commands.iter_mut() {
        let Yaml::Hash(command) = command else {
            continue;
        };
        if command.get(&key("grammar")).and_then(Yaml::as_str) != Some(program) {
            continue;
        }
        let Some(Yaml::Array(have)) = command.get_mut(&key("shapes")) else {
            return Err(no_command());
        };
        if let Some(missing) = want
            .iter()
            .find(|shape| !have.iter().any(|h| h.as_str() == Some(shape)))
        {
            return Err(format!(
                "shape `{missing}` is not one of entry `{name}`'s `{program}` shapes"
            ));
        }
        have.retain(|h| want.iter().any(|shape| h.as_str() == Some(shape)));
        narrowed = true;
    }
    if narrowed {
        Ok(())
    } else {
        Err(no_command())
    }
}

fn emit(program: &str, doc: Hash) -> String {
    let mut out = format!(
        "# Written by maknae tools enable {program} from {VENDOR_TOOLS_DIR}/{program}.yaml.\n"
    );
    YamlEmitter::new(&mut out)
        .dump(&Yaml::Hash(doc))
        .expect("in-memory String emit target cannot fail");
    out.push('\n');
    out
}

struct Source<'a> {
    program: &'a str,
    classes: &'a Hash,
    image: &'a str,
    grammars: &'a GrammarSet,
}

fn dropin(
    source: &Source,
    name: &str,
    body: &Hash,
    shapes: Option<&[String]>,
) -> Result<Dropin, String> {
    let mut entry = body.clone();
    let mut image = Hash::new();
    image.insert(key("ref"), key(source.image));
    if let Some(Yaml::Hash(template_image)) = body.get(&key("image")) {
        if template_image.contains_key(&key("ref")) {
            return Err(format!(
                "entry `{name}` sets image.ref: a template never ships an image"
            ));
        }
        image.extend(template_image.clone());
    }
    entry.insert(key("image"), Yaml::Hash(image));
    if let Some(want) = shapes {
        narrow(&mut entry, name, source.program, want)?;
    }

    let mut classes = Hash::new();
    if let Some(class) = class_of(body, source.classes) {
        if let Some(def) = source.classes.get(&key(class)) {
            classes.insert(key(class), def.clone());
        }
    }
    let mut tools = Hash::new();
    tools.insert(key(name), Yaml::Hash(entry));
    let mut doc = Hash::new();
    doc.insert(key("schema_version"), Yaml::Integer(1));
    doc.insert(key("credential_classes"), Yaml::Hash(classes));
    doc.insert(key("tools"), Yaml::Hash(tools));
    let text = emit(source.program, doc);

    let catalog = ToolsCatalog::parse_with(&text, source.grammars)
        .map_err(|e| format!("entry `{name}` with image `{}`: {e}", source.image))?;
    if let Some(first) = catalog.disabled().first() {
        return Err(format!(
            "entry `{name}` with image `{}`: {}: {}",
            source.image, first.entry, first.reason
        ));
    }
    let parsed = catalog
        .entry(name)
        .ok_or_else(|| format!("entry `{name}` did not parse"))?;

    let mut grants = Vec::new();
    for (program, command) in &parsed.commands {
        match &command.form {
            CommandForm::Grammar { shapes, .. } => {
                grants.extend(
                    shapes
                        .keys()
                        .map(|shape| format!("Tool({name} {program}:{shape})")),
                );
            }
            CommandForm::Positional(patterns) => {
                grants.extend(
                    patterns
                        .iter()
                        .map(|p| format!("Tool({name} {program} {})", p.canonical())),
                );
            }
            CommandForm::Open => grants.push(format!("Tool({name} {program} *)")),
        }
    }
    let apps = parsed
        .credential
        .iter()
        .filter_map(|class| {
            let app = catalog.class(class)?.app.clone()?;
            Some((class.clone(), app))
        })
        .collect();
    Ok(Dropin {
        entry: name.to_string(),
        text,
        grants,
        apps,
    })
}

pub(crate) fn render(
    program: &str,
    template: &str,
    grammar: &Grammar,
    image: &str,
    entry: Option<&str>,
    shapes: Option<&[String]>,
) -> Result<Vec<Dropin>, String> {
    match (entry, shapes) {
        (None, Some(_)) => return Err("--shapes needs --entry".to_string()),
        (Some(_), Some([])) => return Err("--shapes names no shape".to_string()),
        _ => {}
    }
    let docs = YamlLoader::load_from_str(template)
        .map_err(|e| format!("the {program} template is not YAML: {e}"))?;
    let [Yaml::Hash(top)] = docs.as_slice() else {
        return Err(format!("the {program} template must be one YAML mapping"));
    };
    if top.get(&key("schema_version")) != Some(&Yaml::Integer(1)) {
        return Err(format!("the {program} template needs `schema_version: 1`"));
    }
    let classes = mapping(top, "credential_classes")?;
    let tools = mapping(top, "tools")?;
    if top.len() != 3 {
        return Err(format!(
            "the {program} template has keys besides schema_version, credential_classes and tools"
        ));
    }

    let mut entries = Vec::new();
    let mut owners = BTreeMap::new();
    for (name, body) in tools {
        let (Some(name), Some(body)) = (name.as_str(), body.as_hash()) else {
            return Err(format!("the {program} template has a malformed entry"));
        };
        if let Some(class) = class_of(body, classes) {
            if let Some(first) = owners.insert(class, name) {
                return Err(format!(
                    "credential class `{class}` serves both `{first}` and `{name}`: a template gives each entry its own class"
                ));
            }
        }
        entries.push((name, body));
    }

    let chosen: Vec<_> = entries
        .iter()
        .filter(|(name, _)| entry.is_none_or(|wanted| wanted == *name))
        .collect();
    if chosen.is_empty() {
        let names: Vec<_> = entries.iter().map(|(name, _)| *name).collect();
        return Err(format!(
            "the {program} template has no entry `{}`; its entries are {}",
            entry.unwrap_or_default(),
            names.join(", ")
        ));
    }

    let mut set = GrammarSet::empty();
    set.grammars.insert(program.to_string(), grammar.clone());
    let source = Source {
        program,
        classes,
        image,
        grammars: &set,
    };
    chosen
        .into_iter()
        .map(|(name, body)| dropin(&source, name, body, shapes))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use maknae_config::{ToolEntry, ToolsCatalog};

    const TEMPLATE: &str = include_str!("../../../../packaging/common/tools.d/gh.yaml");
    const HOMELAB: &str = include_str!("../../../../packaging/common/tools-homelab.yaml");
    const GRAMMAR: &str = include_str!("../../../../packaging/common/grammars/gh.yaml");
    const SHARED: &str = include_str!("../testdata/template_shared_class.yaml");
    const WITH_REF: &str = include_str!("../testdata/template_with_ref.yaml");

    const OPEN_ENTRY: &str = "  scratch:
    image: { verify: { signature: required, sbom: required } }
    isolation: container
    executes_workspace: true
    network: none
    workspace: rw
    output_to_model: redacted
    commands:
      cargo: { open: true, deny_args: [\"+*\"] }
";

    fn img() -> String {
        format!("ghcr.io/example/tools@sha256:{}", "a".repeat(64))
    }

    fn grammar() -> Grammar {
        Grammar::parse("gh", GRAMMAR).unwrap()
    }

    fn set() -> GrammarSet {
        let mut set = GrammarSet::empty();
        set.grammars.insert("gh".to_string(), grammar());
        set
    }

    fn run(
        template: &str,
        entry: Option<&str>,
        shapes: Option<&[String]>,
    ) -> Result<Vec<Dropin>, String> {
        render("gh", template, &grammar(), &img(), entry, shapes)
    }

    fn parsed(text: &str, name: &str) -> (ToolEntry, ToolsCatalog) {
        let catalog = ToolsCatalog::parse_with(text, &set()).unwrap();
        (catalog.entry(name).unwrap().clone(), catalog)
    }

    fn err(result: Result<Vec<Dropin>, String>) -> String {
        match result {
            Ok(_) => panic!("expected an error"),
            Err(e) => e,
        }
    }

    const NAMES: [&str; 4] = [
        "github-read",
        "github-post",
        "github-issues-read",
        "github-issues-write",
    ];

    #[test]
    fn render_writes_one_valid_dropin_per_entry() {
        let out = run(TEMPLATE, None, None).unwrap();
        let names: Vec<_> = out.iter().map(|d| d.entry.as_str()).collect();
        assert_eq!(names, NAMES);
        for d in &out {
            assert!(
                d.text.starts_with(&format!(
                    "# Written by maknae tools enable gh from {VENDOR_TOOLS_DIR}/gh.yaml.\n"
                )),
                "{}",
                d.text
            );
            let catalog = ToolsCatalog::parse_with(&d.text, &set()).unwrap();
            assert!(catalog.disabled().is_empty());
            assert_eq!(catalog.entries().count(), 1);
            let e = catalog.entry(&d.entry).unwrap();
            assert_eq!(e.image.as_ref().unwrap().reference, img());
        }
    }

    #[test]
    fn the_template_matches_the_homelab_gh_entries() {
        let home = ToolsCatalog::parse_with(HOMELAB, &set()).unwrap();
        for d in run(TEMPLATE, None, None).unwrap() {
            let (mine, mine_catalog) = parsed(&d.text, &d.entry);
            let mut theirs = home.entry(&d.entry).unwrap().clone();
            theirs.image.as_mut().unwrap().reference = img();
            assert_eq!(mine, theirs, "{}", d.entry);
            let class = mine.credential.as_deref().unwrap();
            assert_eq!(mine_catalog.class(class), home.class(class), "{class}");
        }
    }

    #[test]
    fn render_refuses_a_bad_image() {
        let bad = [
            "ghcr.io/x/y:latest".to_string(),
            format!("ghcr.io/x/y@sha256:{}", "A".repeat(64)),
            format!("y@sha256:{}", "a".repeat(64)),
        ];
        for image in &bad {
            let e = err(render("gh", TEMPLATE, &grammar(), image, None, None));
            assert!(e.contains(image.as_str()) && e.contains("image"), "{e}");
        }
    }

    #[test]
    fn render_selects_one_entry() {
        let out = run(TEMPLATE, Some("github-post"), None).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].entry, "github-post");
        let e = err(run(TEMPLATE, Some("nope"), None));
        assert!(e.contains("nope"), "{e}");
        for name in NAMES {
            assert!(e.contains(name), "{e}");
        }
    }

    #[test]
    fn render_narrows_shapes() {
        let only = ["pr.comment".to_string()];
        let out = run(TEMPLATE, Some("github-post"), Some(&only)).unwrap();
        assert_eq!(out.len(), 1);
        let (e, _) = parsed(&out[0].text, "github-post");
        let CommandForm::Grammar { shapes, .. } = &e.commands["gh"].form else {
            panic!("not a grammar command");
        };
        assert_eq!(shapes.keys().collect::<Vec<_>>(), ["pr.comment"]);
        assert_eq!(out[0].grants, ["Tool(github-post gh:pr.comment)"]);

        let wide = ["issue.create".to_string()];
        let e = err(run(TEMPLATE, Some("github-post"), Some(&wide)));
        assert!(
            e.contains("issue.create") && e.contains("github-post"),
            "{e}"
        );
        let e = err(run(TEMPLATE, None, Some(&only)));
        assert!(e.contains("--entry"), "{e}");
        let e = err(run(TEMPLATE, Some("github-post"), Some(&[])));
        assert!(e.contains("no shape"), "{e}");
    }

    #[test]
    fn render_narrows_only_the_grammar_command() {
        let out = run(
            TEMPLATE,
            Some("github-read"),
            Some(&["pr.view".to_string()]),
        )
        .unwrap();
        assert_eq!(
            out[0].grants,
            [
                "Tool(github-read gh:pr.view)",
                "Tool(github-read git fetch *)",
                "Tool(github-read git checkout *)"
            ]
        );
        let no_gh = TEMPLATE.replace("grammar: gh", "grammar: other");
        let e = err(run(
            &no_gh,
            Some("github-read"),
            Some(&["pr.view".to_string()]),
        ));
        assert!(
            e.contains("github-read") && e.contains("grammar command"),
            "{e}"
        );
    }

    #[test]
    fn render_lists_grants_and_apps() {
        let out = run(TEMPLATE, Some("github-read"), None).unwrap();
        assert_eq!(
            out[0].grants,
            [
                "Tool(github-read gh:pr.checks)",
                "Tool(github-read gh:pr.diff)",
                "Tool(github-read gh:pr.view)",
                "Tool(github-read git fetch *)",
                "Tool(github-read git checkout *)",
            ]
        );
        assert_eq!(
            out[0].apps,
            [("github-read".to_string(), "maknae-github-read".to_string())]
        );
    }

    #[test]
    fn render_grants_an_open_program() {
        let open = format!("{TEMPLATE}{OPEN_ENTRY}");
        let out = run(&open, Some("scratch"), None).unwrap();
        assert_eq!(out[0].grants, ["Tool(scratch cargo *)"]);
        assert!(out[0].apps.is_empty());
    }

    #[test]
    fn render_refuses_a_class_shared_by_two_entries() {
        let e = err(run(SHARED, None, None));
        assert!(e.contains("github-read"), "{e}");
    }

    #[test]
    fn render_refuses_a_template_with_an_image_ref() {
        let e = err(run(WITH_REF, None, None));
        assert!(e.contains("never ships an image"), "{e}");
    }

    #[test]
    fn render_refuses_a_malformed_template() {
        let cases = [
            ("a: [", "not YAML"),
            ("- a\n", "one YAML mapping"),
            ("a: 1\n---\nb: 2\n", "one YAML mapping"),
            (
                &TEMPLATE.replace("schema_version: 1", "schema_version: 2"),
                "schema_version",
            ),
            (&TEMPLATE.replace("\ntools:\n", "\ntoolz:\n"), "`tools`"),
            (
                &TEMPLATE.replace("\ncredential_classes:\n", "\nclasses:\n"),
                "`credential_classes`",
            ),
            (&format!("{TEMPLATE}extra: 1\n"), "keys besides"),
            (
                &TEMPLATE.replace("  github-read:\n    enabled", "  3:\n    enabled"),
                "malformed",
            ),
        ];
        for (text, needle) in cases {
            let e = err(run(text, None, None));
            assert!(e.contains(needle), "{needle}: {e}");
        }
    }

    #[test]
    fn render_refuses_an_entry_the_catalog_disables() {
        let bad = TEMPLATE.replace("shapes: [pr.view, pr.diff, pr.checks]", "shapes: [no.such]");
        let e = err(run(&bad, None, None));
        assert!(e.contains("github-read"), "{e}");
    }

    #[test]
    fn render_refuses_an_entry_whose_class_is_undefined() {
        let bad = TEMPLATE.replace("credential: github-post", "credential: missing");
        let e = err(run(&bad, None, None));
        assert!(e.contains("github-post"), "{e}");
    }

    #[test]
    fn render_gives_a_classless_entry_no_class_or_app() {
        let none = TEMPLATE.replace("credential: github-post", "credential: none");
        let out = run(&none, Some("github-post"), None).unwrap();
        assert!(out[0].apps.is_empty());
    }
}
