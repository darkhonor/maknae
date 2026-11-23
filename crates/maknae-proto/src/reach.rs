//! A task's reach (#168, ADR-0037 decision 7): per binding, what its tasker and its agent were
//! each observed able to do at submission, sealed into the signed task.
use serde::{Deserialize, Serialize};

/// A forge-neutral operation. `PushHead` is decided on the head repository, every other on the base.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum ForgeOp {
    Read,
    Review,
    IssueWrite,
    PushHead,
    Merge,
}

impl ForgeOp {
    pub const ALL: [ForgeOp; 5] = [
        Self::Read,
        Self::Review,
        Self::IssueWrite,
        Self::PushHead,
        Self::Merge,
    ];

    const fn bit(self) -> u8 {
        match self {
            Self::Read => 1 << 0,
            Self::Review => 1 << 1,
            Self::IssueWrite => 1 << 2,
            Self::PushHead => 1 << 3,
            Self::Merge => 1 << 4,
        }
    }
}

const OPS_BITS: u32 = ForgeOp::ALL.len() as u32;

#[derive(Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(try_from = "u8", into = "u8")]
pub struct ForgeOps(u8);

impl ForgeOps {
    pub const EMPTY: Self = Self(0);

    pub fn from_bits(bits: u8) -> Option<Self> {
        (bits >> OPS_BITS == 0).then_some(Self(bits))
    }

    pub fn bits(self) -> u8 {
        self.0
    }

    pub fn contains(self, op: ForgeOp) -> bool {
        self.0 & op.bit() != 0
    }

    pub fn with(self, op: ForgeOp) -> Self {
        Self(self.0 | op.bit())
    }

    pub fn intersect(self, other: Self) -> Self {
        Self(self.0 & other.0)
    }

    pub fn is_empty(self) -> bool {
        self.0 == 0
    }
}

impl FromIterator<ForgeOp> for ForgeOps {
    fn from_iter<I: IntoIterator<Item = ForgeOp>>(ops: I) -> Self {
        ops.into_iter().fold(Self::EMPTY, Self::with)
    }
}

impl TryFrom<u8> for ForgeOps {
    type Error = String;
    fn try_from(bits: u8) -> Result<Self, String> {
        Self::from_bits(bits).ok_or_else(|| format!("reach bits {bits:#04x} name no operation"))
    }
}

impl From<ForgeOps> for u8 {
    fn from(ops: ForgeOps) -> u8 {
        ops.0
    }
}

impl std::fmt::Debug for ForgeOps {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_set()
            .entries(ForgeOp::ALL.iter().filter(|op| self.contains(**op)))
            .finish()
    }
}

/// The operations on a binding's base repository and on its change's head repository.
#[derive(Clone, Copy, PartialEq, Eq, Default, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields, try_from = "SideReachWire")]
pub struct SideReach {
    base: ForgeOps,
    head: ForgeOps,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SideReachWire {
    base: ForgeOps,
    head: ForgeOps,
}

impl TryFrom<SideReachWire> for SideReach {
    type Error = String;
    fn try_from(w: SideReachWire) -> Result<Self, String> {
        Self::new(w.base, w.head)
    }
}

impl SideReach {
    pub const EMPTY: Self = Self {
        base: ForgeOps::EMPTY,
        head: ForgeOps::EMPTY,
    };

    pub fn new(base: ForgeOps, head: ForgeOps) -> Result<Self, String> {
        if base.contains(ForgeOp::PushHead) {
            return Err("`PushHead` in a base set".into());
        }
        Ok(Self { base, head })
    }

    pub fn base(self) -> ForgeOps {
        self.base
    }

    pub fn head(self) -> ForgeOps {
        self.head
    }

    pub fn intersect(self, other: Self) -> Self {
        Self {
            base: self.base.intersect(other.base),
            head: self.head.intersect(other.head),
        }
    }
}

/// `AtHandOut`: the agent's credential is observed when the task is handed out, not at submission.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum AgentReach {
    Observed(SideReach),
    AtHandOut,
    NoForgeCredential,
}

/// Why a binding's reach is empty. The tag is its encoding in a [`ReachSummary`].
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[repr(u8)]
pub enum EmptyReason {
    HeadGone = 0,
    AgentNotCovered = 1,
    NoForgeCredential = 2,
    NoReachCheck = 3,
}

impl EmptyReason {
    pub fn tag(self) -> u8 {
        self as u8
    }

    pub fn from_tag(tag: u8) -> Option<Self> {
        match tag {
            0 => Some(Self::HeadGone),
            1 => Some(Self::AgentNotCovered),
            2 => Some(Self::NoForgeCredential),
            3 => Some(Self::NoReachCheck),
            _ => None,
        }
    }
}

/// Where the tasker side came from: the tasker's own token, the parent task's sealed reach, or
/// the submitting agent's own credential.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum TaskerBasis {
    Token,
    Parent,
    Submitter,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GitReach {
    pub tasker: SideReach,
    pub basis: TaskerBasis,
    pub agent: AgentReach,
    pub why: Option<EmptyReason>,
}

/// Index-aligned with the task's bindings, one variant per binding kind.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum BindingReach {
    Git(GitReach),
}

impl BindingReach {
    pub(crate) fn has_head_ops(&self) -> bool {
        let BindingReach::Git(git) = self;
        let agent = match git.agent {
            AgentReach::Observed(side) => side,
            AgentReach::AtHandOut | AgentReach::NoForgeCredential => SideReach::EMPTY,
        };
        !git.tasker.head.is_empty() || !agent.head.is_empty()
    }
}

/// Tasker ∩ agent, per side; empty unless the agent side was observed.
pub fn effective_reach(reach: &BindingReach) -> SideReach {
    let BindingReach::Git(git) = reach;
    match git.agent {
        AgentReach::Observed(agent) => git.tasker.intersect(agent),
        AgentReach::AtHandOut | AgentReach::NoForgeCredential => SideReach::EMPTY,
    }
}

/// A binding's effective reach and its empty reason, as a task view shows it: `ops` holds the
/// base ops in bits 0-4 and the head ops in bits 5-9, and `why` the reason's tag.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(try_from = "(u16, Option<u8>)", into = "(u16, Option<u8>)")]
pub struct ReachSummary {
    ops: u16,
    why: Option<u8>,
}

impl ReachSummary {
    pub fn of(reach: &BindingReach) -> Self {
        let BindingReach::Git(git) = reach;
        let effective = effective_reach(reach);
        Self {
            ops: u16::from(effective.base.0) | u16::from(effective.head.0) << OPS_BITS,
            why: git.why.map(EmptyReason::tag),
        }
    }

    pub fn base(self) -> ForgeOps {
        ForgeOps((self.ops & ((1 << OPS_BITS) - 1)) as u8)
    }

    pub fn head(self) -> ForgeOps {
        ForgeOps((self.ops >> OPS_BITS) as u8)
    }

    pub fn why(self) -> Option<EmptyReason> {
        self.why.and_then(EmptyReason::from_tag)
    }
}

impl From<ReachSummary> for (u16, Option<u8>) {
    fn from(s: ReachSummary) -> Self {
        (s.ops, s.why)
    }
}

impl TryFrom<(u16, Option<u8>)> for ReachSummary {
    type Error = String;
    fn try_from((ops, why): (u16, Option<u8>)) -> Result<Self, String> {
        if ops >> (2 * OPS_BITS) != 0 {
            return Err(format!("reach bits {ops:#06x} name no operation"));
        }
        let summary = Self { ops, why };
        SideReach::new(summary.base(), summary.head())?;
        if let Some(tag) = why {
            if EmptyReason::from_tag(tag).is_none() {
                return Err(format!("tag {tag} names no empty reason"));
            }
        }
        Ok(summary)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn every_ops() -> impl Iterator<Item = ForgeOps> {
        (0..1u8 << OPS_BITS).map(|b| ForgeOps::from_bits(b).unwrap())
    }

    fn every_side() -> Vec<SideReach> {
        every_ops()
            .filter(|b| !b.contains(ForgeOp::PushHead))
            .flat_map(|base| every_ops().map(move |head| SideReach::new(base, head).unwrap()))
            .collect()
    }

    fn git(tasker: SideReach, agent: AgentReach) -> BindingReach {
        BindingReach::Git(GitReach {
            tasker,
            basis: TaskerBasis::Token,
            agent,
            why: None,
        })
    }

    #[test]
    fn each_op_is_one_known_bit() {
        let bits: Vec<u8> = ForgeOp::ALL.iter().map(|op| op.bit()).collect();
        assert_eq!(bits, [1, 2, 4, 8, 16]);
        assert_eq!(
            ForgeOp::ALL.into_iter().collect::<ForgeOps>().bits(),
            (1 << OPS_BITS) - 1
        );
        for bits in 0..=u8::MAX {
            assert_eq!(
                ForgeOps::from_bits(bits).is_some(),
                bits < 1 << 5,
                "{bits:#x}"
            );
        }
        let some: ForgeOps = [ForgeOp::Merge, ForgeOp::Read].into_iter().collect();
        assert_eq!(format!("{some:?}"), "{Read, Merge}");
        assert_eq!(format!("{:?}", ForgeOps::EMPTY), "{}");
    }

    #[test]
    fn effective_reach_is_the_per_side_intersection() {
        let sides = every_side();
        assert_eq!(sides.len(), 16 * 32);
        for &tasker in &sides {
            for &agent in sides.iter().step_by(7) {
                let effective = effective_reach(&git(tasker, AgentReach::Observed(agent)));
                for op in ForgeOp::ALL {
                    assert_eq!(
                        effective.base().contains(op),
                        tasker.base().contains(op) && agent.base().contains(op),
                        "{tasker:?} {agent:?} {op:?}"
                    );
                    assert_eq!(
                        effective.head().contains(op),
                        tasker.head().contains(op) && agent.head().contains(op),
                        "{tasker:?} {agent:?} {op:?}"
                    );
                }
            }
            for agent in [AgentReach::AtHandOut, AgentReach::NoForgeCredential] {
                assert_eq!(
                    effective_reach(&git(tasker, agent)),
                    SideReach::EMPTY,
                    "{agent:?}"
                );
            }
        }
    }

    #[test]
    fn reach_summary_carries_no_side() {
        use ForgeOp::*;
        let tasker = SideReach::new(
            [Read, Review, Merge].into_iter().collect(),
            [PushHead, Read].into_iter().collect(),
        )
        .unwrap();
        let agent = SideReach::new(
            [Read, IssueWrite].into_iter().collect(),
            [PushHead].into_iter().collect(),
        )
        .unwrap();
        let reach = BindingReach::Git(GitReach {
            tasker,
            basis: TaskerBasis::Parent,
            agent: AgentReach::Observed(agent),
            why: Some(EmptyReason::HeadGone),
        });
        let summary = ReachSummary::of(&reach);
        assert_eq!(summary.base(), [Read].into_iter().collect());
        assert_eq!(summary.head(), [PushHead].into_iter().collect());
        assert_eq!(summary.why(), Some(EmptyReason::HeadGone));
        let mut bytes = Vec::new();
        ciborium::into_writer(&summary, &mut bytes).unwrap();
        assert_eq!(bytes, [0x82, 0x19, 0x01, 0x01, 0x00]);
        let back: ReachSummary = ciborium::from_reader(bytes.as_slice()).unwrap();
        assert_eq!(back, summary);

        let at_hand_out = BindingReach::Git(GitReach {
            agent: AgentReach::AtHandOut,
            why: None,
            ..match reach {
                BindingReach::Git(g) => g,
            }
        });
        let summary = ReachSummary::of(&at_hand_out);
        assert!(summary.base().is_empty() && summary.head().is_empty());
        let mut bytes = Vec::new();
        ciborium::into_writer(&summary, &mut bytes).unwrap();
        assert_eq!(bytes, [0x82, 0x00, 0xf6]);
    }

    #[test]
    fn every_empty_reason_has_one_tag() {
        let reasons = [
            EmptyReason::HeadGone,
            EmptyReason::AgentNotCovered,
            EmptyReason::NoForgeCredential,
            EmptyReason::NoReachCheck,
        ];
        for reason in reasons {
            assert_eq!(EmptyReason::from_tag(reason.tag()), Some(reason));
        }
        let tags: Vec<u8> = reasons.iter().map(|r| r.tag()).collect();
        assert_eq!(tags, [0, 1, 2, 3]);
        for tag in 4..=u8::MAX {
            assert_eq!(EmptyReason::from_tag(tag), None, "{tag}");
        }
    }
}
