//! The board verbs' switches (#695).
#[cfg(any(test, feature = "hermetic-test-seam"))]
use std::collections::BTreeSet;

use maknae_config::AgentId;

pub trait BoardSwitches: Send + Sync {
    fn site(&self) -> bool;
    fn agent(&self, agent: &AgentId) -> bool;
}

/// The production switches until #698: the board is served nowhere.
pub struct SwitchesOff;

impl BoardSwitches for SwitchesOff {
    fn site(&self) -> bool {
        false
    }

    fn agent(&self, _: &AgentId) -> bool {
        false
    }
}

#[cfg(any(test, feature = "hermetic-test-seam"))]
#[derive(Clone, Debug, Default)]
pub struct FixedSwitches {
    pub site: bool,
    pub agents: BTreeSet<AgentId>,
}

#[cfg(any(test, feature = "hermetic-test-seam"))]
impl BoardSwitches for FixedSwitches {
    fn site(&self) -> bool {
        self.site
    }

    fn agent(&self, agent: &AgentId) -> bool {
        self.agents.contains(agent)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_production_switches_are_off() {
        let hobi = AgentId::parse("sentinel-695-hobi").unwrap();
        assert!(!SwitchesOff.site());
        assert!(!SwitchesOff.agent(&hobi));
    }
}
