//! What a tasker's client proposes to bind a task to: links in the tasker's own
//! prompt and the remotes of the checkout it runs in, matched against the `git`
//! forges the catalog names. The kernel re-checks every binding at intake.

use maknae_proto::{Binding, BindingRequest, GitRef};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Provider {
    Github,
    Gitlab,
}

impl Provider {
    pub fn parse(s: &str) -> Option<Provider> {
        match s {
            "github" => Some(Provider::Github),
            "gitlab" => Some(Provider::Gitlab),
            _ => None,
        }
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Forge {
    pub host: String,
    pub provider: Provider,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Subject {
    Host(String),
    Written(String),
    Ref(GitRef),
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Reason {
    UnknownServer,
    NotHttps,
    AmbiguousShorthand,
    AmbiguousForge,
    OverTheBound,
    NotInParent,
    NoForgeList,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Unbound {
    pub subject: Subject,
    pub reason: Reason,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Origin {
    Prompt,
    WorkingDirectory,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Found {
    Ref(GitRef),
    Bare { base: String, quoted: bool },
    Unbound(Unbound),
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Hint {
    pub origin: Origin,
    pub found: Found,
}

pub trait HintSource {
    fn hints(&self, prompt: &str, forges: Option<&[Forge]>) -> Vec<Hint>;
}

pub struct Links;

impl HintSource for Links {
    fn hints(&self, prompt: &str, forges: Option<&[Forge]>) -> Vec<Hint> {
        prompt
            .split(char::is_whitespace)
            .filter_map(|word| match link_start(word) {
                Some((at, https)) => link(&word[at..], https, forges),
                None => written_ref(word, forges),
            })
            .map(|found| Hint {
                origin: Origin::Prompt,
                found,
            })
            .collect()
    }
}

/// Where a `http://` or `https://` link starts in `word`, and whether it is https.
fn link_start(word: &str) -> Option<(usize, bool)> {
    let b = word.as_bytes();
    (0..b.len()).find_map(|i| {
        let rest = &b[i..];
        let starts = |scheme: &[u8]| {
            rest.get(..scheme.len())
                .is_some_and(|s| s.eq_ignore_ascii_case(scheme))
        };
        if starts(b"https://") {
            Some((i, true))
        } else if starts(b"http://") {
            Some((i, false))
        } else {
            None
        }
    })
}

const LINK_ENDS: &[char] = &[
    '<', '>', '"', '\'', '`', '(', ')', '[', ']', '{', '}', '|', '\\', '^',
];
const TRAILING: &[char] = &['.', ',', ';', ':', '!', '?'];

fn link(word: &str, https: bool, forges: Option<&[Forge]>) -> Option<Found> {
    let after = &word[word.find("://")? + 3..];
    let after = after.split(LINK_ENDS).next().unwrap_or("");
    let after = after.trim_end_matches(TRAILING);
    let authority_end = after.find(['/', '?', '#']).unwrap_or(after.len());
    let authority = &after[..authority_end];
    let host_port = authority.rsplit('@').next().unwrap_or("");
    if host_port.is_empty() {
        return None;
    }
    let host_port = host_port.to_ascii_lowercase();
    let path = &after[authority_end..];
    let path = &path[..path.find(['?', '#']).unwrap_or(path.len())];
    let unbound = |reason| {
        Some(Found::Unbound(Unbound {
            subject: Subject::Host(host_port.clone()),
            reason,
        }))
    };
    if !https {
        return unbound(Reason::NotHttps);
    }
    let Some(forges) = forges else {
        return unbound(Reason::NoForgeList);
    };
    let forge = match one_of(forges.iter().filter(|f| f.host == host_port)) {
        Match::One(forge) => forge,
        Match::None => return unbound(Reason::UnknownServer),
        Match::Several => return unbound(Reason::AmbiguousForge),
    };
    let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    let (base, change) = match forge.provider {
        Provider::Github => {
            let (owner, repo) = (segments.first()?, segments.get(1)?);
            let change = match (segments.get(2), segments.get(3)) {
                (Some(&"pull"), Some(n)) => number(n),
                _ => None,
            };
            (format!("{owner}/{}", without_git(repo)), change)
        }
        Provider::Gitlab => {
            let dash = segments.iter().position(|s| *s == "-");
            let project = &segments[..dash.unwrap_or(segments.len())];
            let change = match dash.map(|d| (segments.get(d + 1), segments.get(d + 2))) {
                Some((Some(&"merge_requests"), Some(n))) => number(n),
                _ => None,
            };
            let (last, group) = project.split_last()?;
            let mut base = group.join("/");
            base.push('/');
            base.push_str(without_git(last));
            (base, change)
        }
    };
    git_ref(forge, base, change).map(Found::Ref)
}

enum Match<'f> {
    One(&'f Forge),
    None,
    Several,
}

/// The forge among `matches`, an entry that repeats one forge counted once.
fn one_of<'f>(mut matches: impl Iterator<Item = &'f Forge>) -> Match<'f> {
    let Some(first) = matches.next() else {
        return Match::None;
    };
    if matches.all(|f| f == first) {
        Match::One(first)
    } else {
        Match::Several
    }
}

/// The forge a shorthand names: the only distinct `git` forge.
fn the_one_forge(forges: Option<&[Forge]>) -> Result<&Forge, Reason> {
    match forges.map(|f| one_of(f.iter())) {
        None | Some(Match::None) => Err(Reason::NoForgeList),
        Some(Match::Several) => Err(Reason::AmbiguousShorthand),
        Some(Match::One(forge)) => Ok(forge),
    }
}

fn without_git(segment: &str) -> &str {
    segment.strip_suffix(".git").unwrap_or(segment)
}

fn number(s: &str) -> Option<u64> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse().ok().filter(|n| *n > 0)
}

/// Whether `base` names a repository on `provider`.
fn names_a_repository(provider: Provider, base: &str) -> bool {
    maknae_proto::repository_path_is_acceptable(base)
        && match provider {
            Provider::Github => {
                let mut segments = base.split('/');
                segments
                    .next()
                    .is_some_and(|owner| !github_reserved_first_segment(owner))
                    && segments.count() == 1
            }
            Provider::Gitlab => true,
        }
}

fn git_ref(forge: &Forge, base: String, change: Option<u64>) -> Option<GitRef> {
    (maknae_proto::server_is_acceptable(&forge.host) && names_a_repository(forge.provider, &base))
        .then(|| GitRef {
            server: forge.host.clone(),
            base,
            change,
        })
}

const OPENERS: &[char] = &['(', '[', '{', '<', '"', '\'', '*', '_'];
const CLOSERS: &[char] = &[
    '.', ',', ';', ':', '!', '?', ')', ']', '}', '>', '"', '\'', '*',
];

/// A shorthand `owner/repo#N` or `owner/repo!N`, or a bare `owner/repo`.
fn written_ref(word: &str, forges: Option<&[Forge]>) -> Option<Found> {
    let core = word.trim_start_matches(OPENERS).trim_end_matches(CLOSERS);
    let (inner, quoted) = match core.strip_prefix('`').and_then(|c| c.strip_suffix('`')) {
        Some(inner) => (inner, true),
        None => (core, false),
    };
    if inner.contains('`') {
        return None;
    }
    let Some(at) = inner.find(['#', '!']) else {
        return maknae_proto::repository_path_is_acceptable(inner).then(|| Found::Bare {
            base: inner.to_owned(),
            quoted,
        });
    };
    let (base, n) = (&inner[..at], number(&inner[at + 1..])?);
    let sigil = if inner.as_bytes()[at] == b'#' {
        Sigil::Hash
    } else {
        Sigil::Bang
    };
    if !maknae_proto::repository_path_is_acceptable(base) {
        return None;
    }
    let forge = match the_one_forge(forges) {
        Ok(forge) => forge,
        Err(reason) => {
            return Some(Found::Unbound(Unbound {
                subject: Subject::Written(inner.to_owned()),
                reason,
            }))
        }
    };
    let change = shorthand_change(forge.provider, sigil)?.then_some(n);
    git_ref(forge, base.to_owned(), change).map(Found::Ref)
}

/// A remote's host (no userinfo, no port, lowercase) and repository path.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct RemoteUrl {
    host: String,
    path: String,
}

impl RemoteUrl {
    pub fn host(&self) -> &str {
        &self.host
    }

    pub fn path(&self) -> &str {
        &self.path
    }
}

pub struct Remotes(pub Vec<RemoteUrl>);

impl HintSource for Remotes {
    fn hints(&self, _prompt: &str, forges: Option<&[Forge]>) -> Vec<Hint> {
        self.0
            .iter()
            .filter_map(|remote| remote_found(remote, forges))
            .map(|found| Hint {
                origin: Origin::WorkingDirectory,
                found,
            })
            .collect()
    }
}

fn hostname(host: &str) -> &str {
    match host.find(']') {
        Some(end) if host.starts_with('[') => &host[..=end],
        _ => host.split(':').next().unwrap_or(host),
    }
}

fn remote_found(remote: &RemoteUrl, forges: Option<&[Forge]>) -> Option<Found> {
    let unbound = |reason| {
        Some(Found::Unbound(Unbound {
            subject: Subject::Host(remote.host.clone()),
            reason,
        }))
    };
    let Some(forges) = forges else {
        return unbound(Reason::NoForgeList);
    };
    match one_of(forges.iter().filter(|f| hostname(&f.host) == remote.host)) {
        Match::One(forge) => git_ref(forge, remote.path.clone(), None).map(Found::Ref),
        Match::None => unbound(Reason::UnknownServer),
        Match::Several => unbound(Reason::AmbiguousForge),
    }
}

/// A `.git/config` that git itself would refuse to read.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Malformed;

/// Every `remote.<name>.url` in `text`, in file order. Only the host and the path
/// of a URL are ever copied out of `text`; `include` and `insteadOf` are not followed.
pub fn git_config_remotes(text: &[u8]) -> Result<Vec<RemoteUrl>, Malformed> {
    let mut out = Vec::new();
    let mut section: Option<bool> = None;
    let mut pos = if text.starts_with(b"\xef\xbb\xbf") {
        3
    } else {
        0
    };
    while let Some(&c) = text.get(pos) {
        match c {
            b' ' | b'\t' | b'\r' | b'\n' => pos += 1,
            b'#' | b';' => pos = line_end(text, pos),
            b'[' => {
                let (next, remote) = section_header(text, pos + 1)?;
                section = Some(remote);
                pos = next;
            }
            c if c.is_ascii_alphabetic() => {
                let remote = section.ok_or(Malformed)?;
                let start = pos;
                while text
                    .get(pos)
                    .is_some_and(|b| b.is_ascii_alphanumeric() || *b == b'-')
                {
                    pos += 1;
                }
                let url = text[start..pos].eq_ignore_ascii_case(b"url");
                while matches!(text.get(pos), Some(b' ' | b'\t')) {
                    pos += 1;
                }
                match text.get(pos..).unwrap_or_default() {
                    [] | [b'\n', ..] | [b'\r', b'\n', ..] => {}
                    [b'=', ..] => {
                        let value = Value::at(text, pos + 1);
                        if remote && url {
                            out.extend(remote_url(value.clone()));
                        }
                        pos = value.end()?;
                    }
                    _ => return Err(Malformed),
                }
            }
            _ => return Err(Malformed),
        }
    }
    Ok(out)
}

fn line_end(text: &[u8], pos: usize) -> usize {
    text[pos..]
        .iter()
        .position(|b| *b == b'\n')
        .map_or(text.len(), |n| pos + n + 1)
}

/// Parses a section header after its `[`; answers where it ends and whether it
/// names a remote (`[remote "x"]` or `[remote.x]`, the section name in any case).
fn section_header(text: &[u8], mut pos: usize) -> Result<(usize, bool), Malformed> {
    let start = pos;
    while text
        .get(pos)
        .is_some_and(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.'))
    {
        pos += 1;
    }
    let name = &text[start..pos];
    if name.is_empty() {
        return Err(Malformed);
    }
    match text.get(pos) {
        Some(b']') => {
            let remote = match name.iter().position(|b| *b == b'.') {
                Some(dot) => name[..dot].eq_ignore_ascii_case(b"remote"),
                None => false,
            };
            Ok((pos + 1, remote))
        }
        Some(b' ' | b'\t') => {
            while matches!(text.get(pos), Some(b' ' | b'\t')) {
                pos += 1;
            }
            if text.get(pos) != Some(&b'"') {
                return Err(Malformed);
            }
            pos += 1;
            loop {
                match text.get(pos) {
                    None | Some(b'\n') => return Err(Malformed),
                    Some(b'"') => break,
                    Some(b'\\') => pos += 2,
                    Some(_) => pos += 1,
                }
            }
            if text.get(pos + 1) != Some(&b']') {
                return Err(Malformed);
            }
            Ok((pos + 2, name.eq_ignore_ascii_case(b"remote")))
        }
        _ => Err(Malformed),
    }
}

/// A config value's bytes as git decodes them, read lazily from the file so that
/// nothing the caller does not keep is ever copied.
#[derive(Clone)]
struct Value<'a> {
    text: &'a [u8],
    pos: usize,
    quote: bool,
    comment: bool,
    emitted: bool,
    space: usize,
    flush: usize,
    ready: Option<u8>,
    done: bool,
    error: bool,
}

impl<'a> Value<'a> {
    fn at(text: &'a [u8], pos: usize) -> Value<'a> {
        Value {
            text,
            pos,
            quote: false,
            comment: false,
            emitted: false,
            space: 0,
            flush: 0,
            ready: None,
            done: false,
            error: false,
        }
    }

    /// Where the entry after this value starts.
    fn end(mut self) -> Result<usize, Malformed> {
        while self.next().is_some() {}
        if self.error {
            Err(Malformed)
        } else {
            Ok(self.pos)
        }
    }

    fn next_char(&mut self) -> u8 {
        match self.text.get(self.pos..).unwrap_or_default() {
            [] => b'\n',
            [b'\r', b'\n', ..] => {
                self.pos += 2;
                b'\n'
            }
            [c, ..] => {
                self.pos += 1;
                *c
            }
        }
    }
}

impl Iterator for Value<'_> {
    type Item = u8;

    fn next(&mut self) -> Option<u8> {
        loop {
            if self.flush > 0 {
                self.flush -= 1;
                return Some(b' ');
            }
            if let Some(b) = self.ready.take() {
                return Some(b);
            }
            if self.done {
                return None;
            }
            let c = self.next_char();
            if c == b'\n' {
                self.error |= self.quote;
                self.done = true;
                continue;
            }
            if self.comment {
                continue;
            }
            if !self.quote && c.is_ascii_whitespace() {
                if self.emitted {
                    self.space += 1;
                }
                continue;
            }
            if !self.quote && matches!(c, b';' | b'#') {
                self.comment = true;
                continue;
            }
            self.flush = std::mem::take(&mut self.space);
            let out = match c {
                b'\\' => match self.next_char() {
                    b'\n' => continue,
                    b't' => b'\t',
                    b'b' => 0x08,
                    b'n' => b'\n',
                    e @ (b'\\' | b'"') => e,
                    _ => {
                        self.error = true;
                        self.done = true;
                        self.flush = 0;
                        continue;
                    }
                },
                b'"' => {
                    self.quote = !self.quote;
                    continue;
                }
                c => c,
            };
            self.emitted = true;
            self.ready = Some(out);
        }
    }
}

const REMOTE_SCHEMES: [&[u8]; 6] = [b"ssh", b"git+ssh", b"ssh+git", b"https", b"http", b"git"];
const REMOTE_PART_MAX: usize = 512;

/// The host and path of a remote URL, read past any userinfo without copying it.
/// Answers `None` for a local path, another scheme, or a URL git could not reach.
fn remote_url<I: Iterator<Item = u8> + Clone>(url: I) -> Option<RemoteUrl> {
    let scheme_len = url
        .clone()
        .take_while(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'-' | b'.'))
        .count();
    let mut after_scheme = url.clone().skip(scheme_len);
    let is_url = scheme_len > 0
        && after_scheme.next() == Some(b':')
        && after_scheme.next() == Some(b'/')
        && after_scheme.next() == Some(b'/');
    let (host_at, host_len, path_at) = if is_url {
        if !REMOTE_SCHEMES.iter().any(|s| {
            url.clone()
                .take(scheme_len)
                .map(|b| b.to_ascii_lowercase())
                .eq(s.iter().copied())
        }) {
            return None;
        }
        let authority_at = scheme_len + 3;
        let authority_len = url
            .clone()
            .skip(authority_at)
            .take_while(|b| *b != b'/')
            .count();
        let userinfo = last_at(url.clone().skip(authority_at).take(authority_len));
        let host_at = authority_at + userinfo;
        (
            host_at,
            authority_len - userinfo,
            authority_at + authority_len,
        )
    } else {
        let before_slash = url.clone().take_while(|b| *b != b'/').count();
        let host_at = last_at(url.clone().take(before_slash));
        let colon = bracket_aware_colon(url.clone().skip(host_at).take(before_slash - host_at))?;
        (host_at, colon, host_at + colon + 1)
    };
    let host_port = url.clone().skip(host_at).take(host_len);
    let name_len = match host_port.clone().next() {
        Some(b'[') => host_port.clone().position(|b| b == b']')? + 1,
        _ => host_port.clone().take_while(|b| *b != b':').count(),
    };
    let mut port = host_port.clone().skip(name_len);
    if is_url && port.next() == Some(b':') && !port.all(|b| b.is_ascii_digit()) {
        return None;
    }
    let name = host_port.take(name_len);
    let host_ok = name_len > 0
        && name_len <= maknae_proto::SERVER_MAX_BYTES
        && name
            .clone()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'[' | b']' | b':'));
    let path = url.clone().skip(path_at);
    let path_ok = path.clone().take(REMOTE_PART_MAX + 1).count() <= REMOTE_PART_MAX
        && path
            .clone()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b'/'));
    if !host_ok || !path_ok {
        return None;
    }
    let host: String = name.map(|b| char::from(b.to_ascii_lowercase())).collect();
    let path: String = path.map(char::from).collect();
    let path = without_git(path.trim_matches('/')).to_owned();
    Some(RemoteUrl { host, path })
}

/// How many bytes precede the host: up to and including the last `@`, or none.
fn last_at(bytes: impl Iterator<Item = u8>) -> usize {
    bytes
        .enumerate()
        .filter(|(_, b)| *b == b'@')
        .last()
        .map_or(0, |(i, _)| i + 1)
}

fn bracket_aware_colon(bytes: impl Iterator<Item = u8>) -> Option<usize> {
    let mut inside = false;
    for (i, b) in bytes.enumerate() {
        match b {
            b'[' => inside = true,
            b']' => inside = false,
            b':' if !inside => return Some(i),
            _ => {}
        }
    }
    None
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Sigil {
    Hash,
    Bang,
}

/// F11: whether `owner/repo<sigil>N` names change `N` on `provider` (`Some(true)`),
/// only the repository (`Some(false)`), or is not a shorthand there (`None`).
pub fn shorthand_change(provider: Provider, sigil: Sigil) -> Option<bool> {
    match (provider, sigil) {
        (Provider::Github, Sigil::Hash) => Some(true),
        (Provider::Github, Sigil::Bang) => None,
        (Provider::Gitlab, Sigil::Hash) => Some(false),
        (Provider::Gitlab, Sigil::Bang) => Some(true),
    }
}

/// F10: a bare `owner/repo` binds only in backticks or when it is a working-directory remote.
pub fn bare_owner_repo_binds(quoted: bool, equals_a_remote: bool) -> bool {
    quoted || equals_a_remote
}

/// F12: first path segments that are GitHub's own pages, not owners.
const GITHUB_RESERVED: [&str; 25] = [
    "features",
    "orgs",
    "settings",
    "marketplace",
    "topics",
    "collections",
    "sponsors",
    "login",
    "logout",
    "join",
    "pricing",
    "explore",
    "notifications",
    "about",
    "site",
    "security",
    "enterprise",
    "apps",
    "organizations",
    "users",
    "search",
    "trending",
    "new",
    "codespaces",
    "copilot",
];

pub fn github_reserved_first_segment(segment: &str) -> bool {
    GITHUB_RESERVED
        .iter()
        .any(|r| r.eq_ignore_ascii_case(segment))
}

#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct Chosen {
    pub bindings: Vec<BindingRequest>,
    pub unbound: Vec<Unbound>,
}

/// The bindings to submit: `sources`' candidates in order, without duplicates or a
/// repository a change on it already names, only what `parent` holds when there is
/// one, cut to what a submission may carry. Everything not bound is in `unbound`.
pub fn choose(
    sources: &[&dyn HintSource],
    prompt: &str,
    forges: Option<&[Forge]>,
    parent: Option<&[Binding]>,
) -> Chosen {
    let hints: Vec<Hint> = sources
        .iter()
        .flat_map(|s| s.hints(prompt, forges))
        .collect();
    let remotes: Vec<&GitRef> = hints
        .iter()
        .filter_map(|h| match (&h.origin, &h.found) {
            (Origin::WorkingDirectory, Found::Ref(g)) => Some(g),
            _ => None,
        })
        .collect();
    let mut unbound = Vec::new();
    let mut note = |u: Unbound| {
        if !unbound.contains(&u) {
            unbound.push(u);
        }
    };
    let mut refs: Vec<GitRef> = Vec::new();
    for hint in &hints {
        let found = match &hint.found {
            Found::Ref(g) => Some(g.clone()),
            Found::Unbound(u) => {
                note(u.clone());
                None
            }
            Found::Bare { base, quoted } => {
                let remote = remotes.iter().find(|r| r.base == *base);
                if !bare_owner_repo_binds(*quoted, remote.is_some()) {
                    continue;
                }
                match (remote, the_one_forge(forges)) {
                    (Some(r), _) => Some(GitRef {
                        server: r.server.clone(),
                        base: base.clone(),
                        change: None,
                    }),
                    (None, Ok(forge)) => git_ref(forge, base.clone(), None),
                    (None, Err(reason)) => {
                        note(Unbound {
                            subject: Subject::Written(base.clone()),
                            reason,
                        });
                        None
                    }
                }
            }
        };
        if let Some(g) = found.filter(|g| !refs.contains(g)) {
            refs.push(g);
        }
    }
    if let Some(parent) = parent {
        refs.retain(|g| {
            let held = parent.iter().any(|Binding::Git(p)| {
                p.server == g.server && p.base == g.base && p.change == g.change
            });
            if !held {
                note(Unbound {
                    subject: Subject::Ref(g.clone()),
                    reason: Reason::NotInParent,
                });
            }
            held
        });
    }
    let changed: Vec<(String, String)> = refs
        .iter()
        .filter(|g| g.change.is_some())
        .map(|g| (g.server.clone(), g.base.clone()))
        .collect();
    refs.retain(|g| g.change.is_some() || !changed.contains(&(g.server.clone(), g.base.clone())));
    let mut bindings = Vec::new();
    let mut cut = false;
    for g in refs {
        if !cut && bindings.len() < maknae_proto::TASK_BINDINGS_MAX {
            bindings.push(BindingRequest::Git(g.clone()));
            cut = maknae_proto::bindings_encoded_len(&bindings)
                > maknae_proto::TASK_BINDING_REQUESTS_MAX_BYTES;
            if !cut {
                continue;
            }
            bindings.pop();
        }
        cut = true;
        note(Unbound {
            subject: Subject::Ref(g),
            reason: Reason::OverTheBound,
        });
    }
    Chosen { bindings, unbound }
}

#[cfg(test)]
mod tests {
    use super::*;
    use maknae_proto::{
        bindings_encoded_len, decode_request, encode_request, Ask, GitBinding, Labels, Request,
        SecretText, TaskSubmission, Verb, PROTOCOL_VERSION, TASK_BINDINGS_MAX,
        TASK_BINDING_REQUESTS_MAX_BYTES, TASK_SCHEMA, TASK_VERSION,
    };
    use zeroize::Zeroizing;

    fn gh() -> Forge {
        Forge {
            host: "github.com".into(),
            provider: Provider::Github,
        }
    }

    fn gl() -> Forge {
        Forge {
            host: "gitlab.lab.local:8443".into(),
            provider: Provider::Gitlab,
        }
    }

    fn git(server: &str, base: &str, change: Option<u64>) -> GitRef {
        GitRef {
            server: server.into(),
            base: base.into(),
            change,
        }
    }

    fn host(h: &str, reason: Reason) -> Unbound {
        Unbound {
            subject: Subject::Host(h.into()),
            reason,
        }
    }

    fn written(w: &str, reason: Reason) -> Unbound {
        Unbound {
            subject: Subject::Written(w.into()),
            reason,
        }
    }

    fn bound(c: &Chosen) -> Vec<GitRef> {
        c.bindings
            .iter()
            .map(|b| {
                let BindingRequest::Git(g) = b;
                g.clone()
            })
            .collect()
    }

    fn links(prompt: &str, forges: &[Forge]) -> Chosen {
        choose(&[&Links], prompt, Some(forges), None)
    }

    fn remotes(config: &str, forges: &[Forge]) -> Chosen {
        let found = git_config_remotes(config.as_bytes()).expect("well-formed");
        choose(&[&Remotes(found)], "", Some(forges), None)
    }

    #[test]
    fn each_link_form_binds_what_it_names() {
        let pr = git("github.com", "o/r", Some(12));
        let repo = git("github.com", "o/r", None);
        let table: Vec<(&str, Vec<Forge>, GitRef)> = vec![
            ("see https://github.com/o/r/pull/12", vec![gh()], pr.clone()),
            (
                "https://github.com/o/r/pull/12/files",
                vec![gh()],
                pr.clone(),
            ),
            ("https://github.com/o/r/pull/12?w=1", vec![gh()], pr.clone()),
            (
                "https://github.com/o/r/pull/12#discussion_r1",
                vec![gh()],
                pr.clone(),
            ),
            (
                "look at https://github.com/o/r/pull/12.",
                vec![gh()],
                pr.clone(),
            ),
            (
                "https://github.com/o/r/pull/12, then",
                vec![gh()],
                pr.clone(),
            ),
            ("(https://github.com/o/r/pull/12)", vec![gh()], pr.clone()),
            ("<https://github.com/o/r/pull/12>", vec![gh()], pr.clone()),
            (
                "[pr](https://github.com/o/r/pull/12)",
                vec![gh()],
                pr.clone(),
            ),
            ("HTTPS://GitHub.com/o/r/pull/12", vec![gh()], pr.clone()),
            (
                "https://gitlab.lab.local:8443/g/sub/proj/-/merge_requests/7/diffs",
                vec![gh(), gl()],
                git("gitlab.lab.local:8443", "g/sub/proj", Some(7)),
            ),
            (
                "https://gitlab.lab.local:8443/g/sub/proj",
                vec![gl()],
                git("gitlab.lab.local:8443", "g/sub/proj", None),
            ),
            ("https://github.com/o/r", vec![gh()], repo.clone()),
            ("https://github.com/o/r/", vec![gh()], repo.clone()),
            ("https://github.com/o/r/issues", vec![gh()], repo.clone()),
            ("https://github.com/o/r/issues/5", vec![gh()], repo.clone()),
            (
                "https://github.com/o/r/tree/main/src",
                vec![gh()],
                repo.clone(),
            ),
            ("https://github.com/o/r.git", vec![gh()], repo.clone()),
            (
                "triage o/r#4 please",
                vec![gh()],
                git("github.com", "o/r", Some(4)),
            ),
            (
                "triage **o/r#4**.",
                vec![gh()],
                git("github.com", "o/r", Some(4)),
            ),
            ("in `o/r`, fix it", vec![gh()], repo.clone()),
            ("in `o/r#4`", vec![gh()], git("github.com", "o/r", Some(4))),
        ];
        for (prompt, forges, want) in table {
            let c = links(prompt, &forges);
            assert_eq!(bound(&c), vec![want], "{prompt}");
            assert!(c.unbound.is_empty(), "{prompt}: {:?}", c.unbound);
        }
    }

    #[test]
    fn a_look_alike_host_is_not_a_forge() {
        for (prompt, named) in [
            (
                "https://github.com.evil.example/o/r/pull/1",
                "github.com.evil.example",
            ),
            ("https://evilgithub.com/o/r/pull/1", "evilgithub.com"),
            ("https://github.co/o/r/pull/1", "github.co"),
            ("https://github.com:444/o/r/pull/1", "github.com:444"),
            ("https://github.com@evil.example/o/r/pull/1", "evil.example"),
            ("https://u:github.com@evil.example/o/r", "evil.example"),
        ] {
            let c = links(prompt, &[gh()]);
            assert!(c.bindings.is_empty(), "{prompt}");
            assert_eq!(c.unbound, [host(named, Reason::UnknownServer)], "{prompt}");
        }
    }

    #[test]
    fn http_is_never_bound() {
        for prompt in [
            "http://github.com/o/r/pull/1",
            "HTTP://github.com/o/r",
            "http://github.com/o/r/issues",
        ] {
            let c = links(prompt, &[gh()]);
            assert!(c.bindings.is_empty(), "{prompt}");
            assert_eq!(
                c.unbound,
                [host("github.com", Reason::NotHttps)],
                "{prompt}"
            );
        }
    }

    #[test]
    fn the_provider_decides_the_url_form() {
        let c = links("https://github.com/o/r/-/merge_requests/3", &[gh()]);
        assert_eq!(bound(&c), [git("github.com", "o/r", None)]);
        let c = links("https://gitlab.lab.local:8443/o/r/pull/3", &[gl()]);
        assert_eq!(
            bound(&c),
            [git("gitlab.lab.local:8443", "o/r/pull/3", None)]
        );
        let c = links("https://github.com/g/sub/proj", &[gh()]);
        assert_eq!(bound(&c), [git("github.com", "g/sub", None)]);
    }

    #[test]
    fn the_shorthand_sigil_is_read_per_provider() {
        assert_eq!(shorthand_change(Provider::Github, Sigil::Hash), Some(true));
        assert_eq!(shorthand_change(Provider::Github, Sigil::Bang), None);
        assert_eq!(shorthand_change(Provider::Gitlab, Sigil::Hash), Some(false));
        assert_eq!(shorthand_change(Provider::Gitlab, Sigil::Bang), Some(true));
        let lab = |p| bound(&links(p, &[gl()]));
        assert_eq!(lab("o/r!5"), [git("gitlab.lab.local:8443", "o/r", Some(5))]);
        assert_eq!(lab("o/r#5"), [git("gitlab.lab.local:8443", "o/r", None)]);
        assert_eq!(
            bound(&links("o/r#5", &[gh()])),
            [git("github.com", "o/r", Some(5))]
        );
        assert!(links("o/r!5", &[gh()]).bindings.is_empty());
    }

    #[test]
    fn the_shorthand_binds_only_with_exactly_one_git_forge() {
        let c = links("o/r#5", &[gh(), gl()]);
        assert!(c.bindings.is_empty());
        assert_eq!(c.unbound, [written("o/r#5", Reason::AmbiguousShorthand)]);
        let c = links("`o/r`", &[gh(), gl()]);
        assert!(c.bindings.is_empty());
        assert_eq!(c.unbound, [written("o/r", Reason::AmbiguousShorthand)]);
        let c = links("o/r#5", &[]);
        assert_eq!(c.unbound, [written("o/r#5", Reason::NoForgeList)]);
        let c = choose(&[&Links], "o/r#5 and https://github.com/a/b", None, None);
        assert!(c.bindings.is_empty());
        assert_eq!(
            c.unbound,
            [
                written("o/r#5", Reason::NoForgeList),
                host("github.com", Reason::NoForgeList)
            ]
        );
    }

    #[test]
    fn the_shorthand_counts_distinct_hosts() {
        let c = links("o/r#5", &[gh(), gh()]);
        assert_eq!(bound(&c), [git("github.com", "o/r", Some(5))]);
        let other = Forge {
            host: "github.com".into(),
            provider: Provider::Gitlab,
        };
        let c = links("o/r#5", &[gh(), other]);
        assert_eq!(c.unbound, [written("o/r#5", Reason::AmbiguousShorthand)]);
    }

    #[test]
    fn github_reserved_first_segments_are_not_repositories() {
        let reserved = [
            "features",
            "orgs",
            "settings",
            "marketplace",
            "topics",
            "collections",
            "sponsors",
            "login",
            "logout",
            "join",
            "pricing",
            "explore",
            "notifications",
            "about",
            "site",
            "security",
            "enterprise",
            "apps",
            "organizations",
            "users",
            "search",
            "trending",
            "new",
            "codespaces",
            "copilot",
        ];
        for seg in reserved {
            assert!(github_reserved_first_segment(seg), "{seg}");
            assert!(github_reserved_first_segment(&seg.to_uppercase()), "{seg}");
            let c = links(&format!("https://github.com/{seg}/x/pull/3"), &[gh()]);
            assert!(
                c.bindings.is_empty() && c.unbound.is_empty(),
                "{seg}: {c:?}"
            );
            let c = links(&format!("{seg}/x#3"), &[gh()]);
            assert!(
                c.bindings.is_empty() && c.unbound.is_empty(),
                "{seg}: {c:?}"
            );
        }
        assert!(!github_reserved_first_segment("darkhonor"));
        let c = links("https://gitlab.lab.local:8443/settings/x", &[gl()]);
        assert_eq!(
            bound(&c),
            [git("gitlab.lab.local:8443", "settings/x", None)]
        );
    }

    #[test]
    fn candidates_keep_prompt_order_without_duplicates() {
        let c = choose(
            &[
                &Links,
                &Remotes(
                    git_config_remotes(
                        b"[remote \"o\"]\nurl = git@github.com:z/z.git\nurl = git@github.com:b/b\n",
                    )
                    .unwrap(),
                ),
            ],
            "https://github.com/b/b/pull/2 https://github.com/a/a https://github.com/b/b/pull/2 \
             https://github.com/a/a/pull/1 https://github.com/b/b",
            Some(&[gh()]),
            None,
        );
        assert_eq!(
            bound(&c),
            [
                git("github.com", "b/b", Some(2)),
                git("github.com", "a/a", Some(1)),
                git("github.com", "z/z", None),
            ]
        );
        assert!(c.unbound.is_empty());
        let c = links("https://evil.example/x https://evil.example/y", &[gh()]);
        assert_eq!(c.unbound, [host("evil.example", Reason::UnknownServer)]);
    }

    #[test]
    fn the_ninth_candidate_is_cut_with_a_note() {
        let prompt: String = (1..=9)
            .map(|n| format!("https://github.com/o/r/pull/{n} "))
            .collect();
        let c = links(&prompt, &[gh()]);
        let want: Vec<_> = (1..=8).map(|n| git("github.com", "o/r", Some(n))).collect();
        assert_eq!(bound(&c), want);
        assert_eq!(TASK_BINDINGS_MAX, 8);
        assert_eq!(
            c.unbound,
            [Unbound {
                subject: Subject::Ref(git("github.com", "o/r", Some(9))),
                reason: Reason::OverTheBound,
            }]
        );
    }

    fn long_forge() -> Forge {
        Forge {
            host: format!("{}.com", "h".repeat(251)),
            provider: Provider::Github,
        }
    }

    fn long_base(c: char) -> String {
        format!("{c}/{}", "r".repeat(253))
    }

    #[test]
    fn the_byte_bound_cuts_with_a_note() {
        let f = long_forge();
        assert_eq!(f.host.len(), 255);
        let prompt = format!(
            "https://{h}/{a}/pull/1 https://{h}/{b}/pull/2 https://{h}/{c}/pull/3",
            h = f.host,
            a = long_base('a'),
            b = long_base('b'),
            c = long_base('c'),
        );
        let c = links(&prompt, std::slice::from_ref(&f));
        assert_eq!(bound(&c), [git(&f.host, &long_base('a'), Some(1))]);
        assert!(bindings_encoded_len(&c.bindings) <= TASK_BINDING_REQUESTS_MAX_BYTES);
        let mut two = c.bindings.clone();
        two.push(BindingRequest::Git(git(&f.host, &long_base('b'), Some(2))));
        assert!(bindings_encoded_len(&two) > TASK_BINDING_REQUESTS_MAX_BYTES);
        assert_eq!(
            c.unbound,
            [
                Unbound {
                    subject: Subject::Ref(git(&f.host, &long_base('b'), Some(2))),
                    reason: Reason::OverTheBound,
                },
                Unbound {
                    subject: Subject::Ref(git(&f.host, &long_base('c'), Some(3))),
                    reason: Reason::OverTheBound,
                },
            ]
        );
        let short = format!("https://{}/o/r/pull/9", f.host);
        let c = links(&format!("{short} {prompt}"), std::slice::from_ref(&f));
        assert_eq!(
            c.bindings.len(),
            2,
            "maximal candidates are kept up to the cut"
        );
        let with = |len: usize| {
            let second = format!("o/{}", "s".repeat(len - 2));
            let prompt = format!(
                "https://{h}/{a}/pull/1 https://{h}/{second}",
                h = f.host,
                a = long_base('a')
            );
            (links(&prompt, std::slice::from_ref(&f)), second)
        };
        let fits = |len: usize| {
            let (_, second) = with(len);
            let pair = [
                BindingRequest::Git(git(&f.host, &long_base('a'), Some(1))),
                BindingRequest::Git(git(&f.host, &second, None)),
            ];
            bindings_encoded_len(&pair) <= TASK_BINDING_REQUESTS_MAX_BYTES
        };
        let edge = (3..=255)
            .find(|l| !fits(*l))
            .expect("a second base that does not fit");
        assert!(edge > 3 && fits(edge - 1));
        assert_eq!(with(edge - 1).0.bindings.len(), 2, "at the bound");
        let (over, second) = with(edge);
        assert_eq!(over.bindings.len(), 1, "one byte over");
        assert_eq!(
            over.unbound,
            [Unbound {
                subject: Subject::Ref(git(&f.host, &second, None)),
                reason: Reason::OverTheBound,
            }]
        );
    }

    #[test]
    fn a_maximal_candidate_set_is_cut_to_what_submission_decode_accepts() {
        let f = long_forge();
        let prompt = format!(
            "https://{h}/{a}/pull/{n} https://{h}/{b}/pull/{n}",
            h = f.host,
            a = long_base('a'),
            b = long_base('b'),
            n = u64::MAX,
        );
        let c = links(&prompt, &[f]);
        assert_eq!(c.bindings.len(), 1);
        let request = Request {
            protocol_version: PROTOCOL_VERSION,
            verb: Verb::TaskSubmit {
                task: TaskSubmission {
                    schema: TASK_SCHEMA.into(),
                    version: TASK_VERSION,
                    agent: "hobi".into(),
                    ask: Ask::Prompt {
                        prompt: SecretText(Zeroizing::new(prompt.clone())),
                    },
                    labels: Labels {},
                    bindings: c.bindings.clone(),
                },
            },
            task: None,
        };
        let bytes = encode_request(&request).expect("encodes");
        let back = decode_request(&bytes).expect("decodes");
        let Verb::TaskSubmit { task } = back.verb else {
            panic!("not a submission");
        };
        assert_eq!(task.bindings, c.bindings);
    }

    fn parent(refs: &[GitRef]) -> Vec<Binding> {
        refs.iter()
            .map(|g| {
                Binding::Git(GitBinding {
                    server: g.server.clone(),
                    base: g.base.clone(),
                    head: Some("fork/r".into()),
                    change: g.change,
                })
            })
            .collect()
    }

    #[test]
    fn a_sub_task_keeps_only_what_its_parent_holds() {
        let held = parent(&[
            git("github.com", "o/r", Some(1)),
            git("github.com", "o/s", None),
        ]);
        let c = choose(
            &[&Links],
            "https://github.com/o/r/pull/1 https://github.com/o/r/pull/2 \
             https://github.com/o/s/pull/3 https://github.com/o/s `o/t`",
            Some(&[gh()]),
            Some(&held),
        );
        assert_eq!(
            bound(&c),
            [
                git("github.com", "o/r", Some(1)),
                git("github.com", "o/s", None)
            ]
        );
        let not_held = |g| Unbound {
            subject: Subject::Ref(g),
            reason: Reason::NotInParent,
        };
        assert_eq!(
            c.unbound,
            [
                not_held(git("github.com", "o/r", Some(2))),
                not_held(git("github.com", "o/s", Some(3))),
                not_held(git("github.com", "o/t", None)),
            ]
        );
        let c = choose(&[&Links], "`o/s`", Some(&[gh()]), Some(&held));
        assert_eq!(bound(&c), [git("github.com", "o/s", None)]);
        let c = choose(
            &[&Links],
            "https://github.com/o/r",
            Some(&[gh()]),
            Some(&[]),
        );
        assert!(c.bindings.is_empty());
    }

    #[test]
    fn bare_owner_repo_predicate() {
        assert!(bare_owner_repo_binds(true, false));
        assert!(bare_owner_repo_binds(false, true));
        assert!(bare_owner_repo_binds(true, true));
        assert!(!bare_owner_repo_binds(false, false));
        let c = links("and/or TCP/IP src/main.rs N/A o/r", &[gh()]);
        assert!(c.bindings.is_empty() && c.unbound.is_empty(), "{c:?}");
        let wd = Remotes(
            git_config_remotes(b"[remote \"origin\"]\nurl = git@gitlab.lab.local:g/p.git\n")
                .unwrap(),
        );
        let c = choose(&[&Links, &wd], "fix g/p and o/r", Some(&[gh(), gl()]), None);
        assert_eq!(bound(&c), [git("gitlab.lab.local:8443", "g/p", None)]);
        assert!(c.unbound.is_empty());
    }

    #[test]
    fn every_forge_remote_binds_its_repository() {
        let c = remotes(
            "[remote \"origin\"]\n\turl = https://github.com/darkhonor/maknae.git\n\
             \tfetch = +refs/heads/*:refs/remotes/origin/*\n\
             [remote \"lab\"]\n\turl = ssh://git@gitlab.lab.local/g/sub/p.git\n\
             [remote \"fork\"]\n\turl = git@github.com:byeori-bot/maknae\n",
            &[gh(), gl()],
        );
        assert_eq!(
            bound(&c),
            [
                git("github.com", "darkhonor/maknae", None),
                git("gitlab.lab.local:8443", "g/sub/p", None),
                git("github.com", "byeori-bot/maknae", None),
            ]
        );
    }

    #[test]
    fn scp_and_ssh_remotes_match_the_forge_by_hostname_and_seal_its_host() {
        for url in [
            "git@gitlab.lab.local:g/p.git",
            "gitlab.lab.local:g/p",
            "ssh://git@gitlab.lab.local:2222/g/p.git",
            "ssh://GitLab.Lab.Local/g/p/",
            "https://gitlab.lab.local/g/p.git",
            "https://gitlab.lab.local:8443/g/p",
        ] {
            let c = remotes(&format!("[remote \"o\"]\nurl = {url}\n"), &[gh(), gl()]);
            assert_eq!(
                bound(&c),
                [git("gitlab.lab.local:8443", "g/p", None)],
                "{url}"
            );
        }
    }

    const TOKEN: &str = "ghp_SENTINEL168userinfo";

    #[test]
    fn userinfo_never_reaches_a_candidate_or_a_note() {
        let config = format!(
            "[remote \"a\"]\nurl = https://x-access-token:{TOKEN}@github.com/o/r.git\n\
             [remote \"b\"]\nurl = https://u:{TOKEN}@evil.example/o/r\n\
             [remote \"c\"]\nurl = {TOKEN}@bitbucket.org:o/r\n\
             [remote \"d\"]\nurl = ssh://u:{TOKEN}@[::1]:22/o/r\n"
        );
        let c = remotes(&config, &[gh()]);
        assert_eq!(bound(&c), [git("github.com", "o/r", None)]);
        assert_eq!(
            c.unbound,
            [
                host("evil.example", Reason::UnknownServer),
                host("bitbucket.org", Reason::UnknownServer),
                host("[::1]", Reason::UnknownServer),
            ]
        );
        assert!(!format!("{c:?}").contains("SENTINEL"));
        let prompt = format!("https://u:{TOKEN}@evil.example/o/r");
        let c = links(&prompt, &[gh()]);
        assert!(!format!("{c:?}").contains("SENTINEL"));
    }

    #[test]
    fn userinfo_never_reaches_an_owned_value() {
        let config = format!(
            "[remote \"a\"]\nurl = https://x:{TOKEN}@github.com/o/r.git\n\
             url = \"https://x:{TOKEN}@github.com/o/q\" ; quoted\n\
             url = {TOKEN}@github.com:o/p\n\
             url = https://x:{TOKEN}/@github.com/o/n\n\
             url = git@github.com:o/{TOKEN}@x\n"
        );
        let found = git_config_remotes(config.as_bytes()).unwrap();
        assert_eq!(
            found,
            [
                RemoteUrl {
                    host: "github.com".into(),
                    path: "o/r".into()
                },
                RemoteUrl {
                    host: "github.com".into(),
                    path: "o/q".into()
                },
                RemoteUrl {
                    host: "github.com".into(),
                    path: "o/p".into()
                },
            ]
        );
        assert!(!format!("{found:?}").contains("SENTINEL"));
    }

    #[test]
    fn non_forge_remotes_are_reported_not_bound() {
        let c = remotes(
            "[remote \"bb\"]\nurl = git@bitbucket.org:o/r.git\n\
             [remote \"local\"]\nurl = ../other\n\
             [remote \"file\"]\nurl = file:///srv/git/r.git\n\
             [remote \"abs\"]\nurl = /srv/git/r.git\n",
            &[gh()],
        );
        assert!(c.bindings.is_empty());
        assert_eq!(c.unbound, [host("bitbucket.org", Reason::UnknownServer)]);
        let found =
            git_config_remotes(b"[remote \"bb\"]\nurl = git@bitbucket.org:o/r.git\n").unwrap();
        let c = choose(&[&Remotes(found)], "", None, None);
        assert_eq!(c.unbound, [host("bitbucket.org", Reason::NoForgeList)]);
    }

    #[test]
    fn a_remote_matching_two_forges_on_one_hostname_is_not_bound() {
        let ghe = |h: &str| Forge {
            host: h.into(),
            provider: Provider::Github,
        };
        for forges in [
            vec![ghe("ghe.example:8443"), ghe("ghe.example")],
            vec![
                ghe("ghe.example"),
                Forge {
                    host: "ghe.example".into(),
                    provider: Provider::Gitlab,
                },
            ],
        ] {
            let c = remotes("[remote \"o\"]\nurl = git@ghe.example:o/r\n", &forges);
            assert!(c.bindings.is_empty(), "{forges:?}");
            assert_eq!(c.unbound, [host("ghe.example", Reason::AmbiguousForge)]);
        }
        let c = remotes(
            "[remote \"o\"]\nurl = git@ghe.example:o/r\n",
            &[ghe("ghe.example:8443"), ghe("ghe.example:8443")],
        );
        assert_eq!(bound(&c), [git("ghe.example:8443", "o/r", None)]);
    }

    #[test]
    fn quoting_comments_and_section_case_are_parsed_as_git_does() {
        let config = "\u{feff}# url = https://github.com/c/c\n\
             ; [remote \"x\"]\n\
             [REMOTE \"Origin\"]\n\tURL = \"git@github.com:o/a.git\" ; a comment\n\
             [remote \"x\"] url = https://github.com/o/b # c\n\
             [remote.Up]\nUrl=git@github.com:o/c\n\
             [Remote \"q\"]\n  url = \"https://github.com/o/\"d\r\n\
             [remote \"cont\"]\n  url = https://github.com/o/\\\ne\n\
             [remotes \"z\"]\nurl = https://github.com/no/z\n\
             [core]\nurl = https://github.com/no/core\n\tbare\n\
             [remote]\nurl = https://github.com/no/sectionless\n";
        let found = git_config_remotes(config.as_bytes()).unwrap();
        let paths: Vec<_> = found.iter().map(RemoteUrl::path).collect();
        assert_eq!(paths, ["o/a", "o/b", "o/c", "o/d", "o/e"]);
        for bad in [
            "url = https://github.com/o/r\n",
            "[remote \"o\"\nurl = x\n",
            "[remote \"o\"]\nurl = \"https://github.com/o/r\n",
            "[remote \"o\"]\nurl = https://github.com/o/\\q\n",
            "[remote \"o\"]\nurl ; x\n",
            "[remote \"o\"]\n=x\n",
        ] {
            assert_eq!(
                git_config_remotes(bad.as_bytes()),
                Err(Malformed),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn pushurl_and_other_keys_are_ignored() {
        let found = git_config_remotes(
            b"[remote \"o\"]\n\tpushurl = git@github.com:p/q\n\tfetch = +refs/*:refs/*\n\
              \turls = git@github.com:p/r\n\
              [branch \"main\"]\n\tremote = origin\n\turl = git@github.com:p/s\n\
              [url \"git@github.com:\"]\n\tinsteadOf = gh:\n\turl = git@github.com:p/t\n",
        )
        .unwrap();
        assert!(found.is_empty(), "{found:?}");
    }
}
