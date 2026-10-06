use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NodeId(pub u64);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EdgeId(pub u64);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NodeKind(pub u16);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EdgeKind(pub u16);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SubjectId(pub u64);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GraphSpace {
    Shared,
    User(SubjectId),
    Kernel,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProvenanceKind {
    Compiled,
    Seed,
    RootFile,
    Operator,
    Kernel,
}

impl ProvenanceKind {
    pub fn code(self) -> u16 {
        match self {
            Self::Compiled => 1,
            Self::Seed => 2,
            Self::RootFile => 3,
            Self::Operator => 4,
            Self::Kernel => 5,
        }
    }

    pub fn from_code(code: u16) -> Option<Self> {
        match code {
            1 => Some(Self::Compiled),
            2 => Some(Self::Seed),
            3 => Some(Self::RootFile),
            4 => Some(Self::Operator),
            5 => Some(Self::Kernel),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Provenance {
    pub kind: ProvenanceKind,
    pub transition: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttrValue {
    Str(String),
    U64(u64),
}

pub type Attrs = BTreeMap<String, AttrValue>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeRecord {
    pub id: NodeId,
    pub space: GraphSpace,
    pub kind: NodeKind,
    pub key: String,
    pub label: String,
    pub provenance: Provenance,
    pub revision: u64,
    pub attrs: Attrs,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EdgeRecord {
    pub id: EdgeId,
    pub space: GraphSpace,
    pub from: NodeId,
    pub to: NodeId,
    pub kind: EdgeKind,
    pub label: String,
    pub provenance: Provenance,
    pub revision: u64,
    pub attrs: Attrs,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provenance_codes_round_trip_and_are_pinned() {
        let all = [
            (ProvenanceKind::Compiled, 1),
            (ProvenanceKind::Seed, 2),
            (ProvenanceKind::RootFile, 3),
            (ProvenanceKind::Operator, 4),
            (ProvenanceKind::Kernel, 5),
        ];
        for (kind, code) in all {
            assert_eq!(kind.code(), code);
            assert_eq!(ProvenanceKind::from_code(code), Some(kind));
        }
        assert_eq!(ProvenanceKind::from_code(0), None);
        assert_eq!(ProvenanceKind::from_code(6), None);
    }
}
