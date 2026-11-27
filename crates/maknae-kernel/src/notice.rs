//! The kernel's per-agent queue of control-channel notices (#746): bounded, refuse-not-evict,
//! offered until retired.
use std::collections::{BTreeMap, VecDeque};

use maknae_config::AgentId;
use maknae_proto::{Notice, NoticeBody, Tasker, NOTICES_MAX};

pub const NOTICES_PER_TASKER: usize = 2;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Unqueued {
    AgentFull,
    TaskerFull,
}

impl Unqueued {
    pub fn as_str(self) -> &'static str {
        match self {
            Unqueued::AgentFull => "the agent has 8 notices outstanding",
            Unqueued::TaskerFull => "the tasker has 2 notices outstanding for the agent",
        }
    }
}

pub struct NoticeQueue<B: NoticeBody> {
    queues: BTreeMap<AgentId, VecDeque<(Tasker, Notice<B>)>>,
}

impl<B: NoticeBody> Default for NoticeQueue<B> {
    fn default() -> Self {
        Self::new()
    }
}

impl<B: NoticeBody> NoticeQueue<B> {
    pub fn new() -> Self {
        Self {
            queues: BTreeMap::new(),
        }
    }

    pub fn offer(
        &mut self,
        agent: &AgentId,
        tasker: &Tasker,
        notice: Notice<B>,
    ) -> Result<(), Unqueued> {
        let queue = self.queues.entry(agent.clone()).or_default();
        if queue
            .iter()
            .any(|(_, n)| n.task == notice.task && n.body == notice.body)
        {
            return Ok(());
        }
        if queue.len() >= NOTICES_MAX {
            return Err(Unqueued::AgentFull);
        }
        if queue.iter().filter(|(t, _)| t == tasker).count() >= NOTICES_PER_TASKER {
            return Err(Unqueued::TaskerFull);
        }
        queue.push_back((tasker.clone(), notice));
        Ok(())
    }

    pub fn pending(&self, agent: &AgentId) -> Vec<Notice<B>> {
        self.queues
            .get(agent)
            .map(|q| q.iter().map(|(_, n)| n.clone()).collect())
            .unwrap_or_default()
    }

    pub fn retire(&mut self, agent: &AgentId, retired: impl Fn(&Notice<B>) -> bool) {
        if let Some(queue) = self.queues.get_mut(agent) {
            queue.retain(|(_, n)| !retired(n));
            if queue.is_empty() {
                self.queues.remove(agent);
            }
        }
    }

    pub fn retire_all(&mut self, agent: &AgentId) {
        self.queues.remove(agent);
    }

    pub fn agents(&self) -> impl Iterator<Item = &AgentId> {
        self.queues.keys()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use maknae_proto::{AgentNotice, NoticeId, TaskId};

    fn agent(s: &str) -> AgentId {
        AgentId::parse(s).unwrap()
    }

    fn stop(n: u8) -> Notice<AgentNotice> {
        Notice {
            id: NoticeId([n; 16]),
            task: Some(TaskId([n; 16])),
            body: AgentNotice::Stop,
        }
    }

    fn by(uid: u32) -> Tasker {
        Tasker::Uid(uid)
    }

    fn ids(q: &NoticeQueue<AgentNotice>, a: &AgentId) -> Vec<NoticeId> {
        q.pending(a).iter().map(|n| n.id).collect()
    }

    #[test]
    fn each_refusal_reads_as_its_bound() {
        assert_eq!((NOTICES_MAX, NOTICES_PER_TASKER), (8, 2));
        assert_eq!(
            Unqueued::AgentFull.as_str(),
            "the agent has 8 notices outstanding"
        );
        assert_eq!(
            Unqueued::TaskerFull.as_str(),
            "the tasker has 2 notices outstanding for the agent"
        );
    }

    #[test]
    fn a_queue_holds_at_most_eight_per_agent_and_refuses_the_ninth() {
        let mut q = NoticeQueue::new();
        let hobi = agent("hobi");
        for n in 0..8u8 {
            assert_eq!(q.offer(&hobi, &by(1000 + u32::from(n)), stop(n)), Ok(()));
        }
        assert_eq!(q.offer(&hobi, &by(2000), stop(9)), Err(Unqueued::AgentFull));
        assert_eq!(q.pending(&hobi).len(), NOTICES_MAX);
        assert_eq!(
            q.offer(&agent("jin"), &by(2000), stop(9)),
            Ok(()),
            "another agent's queue is its own"
        );
    }

    #[test]
    fn a_full_agent_is_refused_as_full_before_its_tasker_bound_is_read() {
        let mut q = NoticeQueue::new();
        let hobi = agent("hobi");
        for n in 0..6u8 {
            q.offer(&hobi, &by(1000 + u32::from(n)), stop(n)).unwrap();
        }
        for n in 6..8u8 {
            q.offer(&hobi, &by(7), stop(n)).unwrap();
        }
        assert_eq!(q.offer(&hobi, &by(7), stop(9)), Err(Unqueued::AgentFull));
    }

    #[test]
    fn a_tasker_holds_at_most_two_per_agent_and_another_tasker_is_unaffected() {
        let mut q = NoticeQueue::new();
        let hobi = agent("hobi");
        assert_eq!(q.offer(&hobi, &by(1), stop(1)), Ok(()));
        assert_eq!(q.offer(&hobi, &by(1), stop(2)), Ok(()));
        assert_eq!(q.offer(&hobi, &by(1), stop(3)), Err(Unqueued::TaskerFull));
        assert_eq!(q.offer(&hobi, &by(2), stop(4)), Ok(()));
        assert_eq!(
            q.offer(&agent("jin"), &by(1), stop(5)),
            Ok(()),
            "the bound is per agent"
        );
        assert_eq!(q.pending(&hobi).len(), 3);
    }

    #[test]
    fn a_refusal_drops_nothing_already_queued() {
        let mut q = NoticeQueue::new();
        let hobi = agent("hobi");
        q.offer(&hobi, &by(1), stop(1)).unwrap();
        q.offer(&hobi, &by(1), stop(2)).unwrap();
        let before = q.pending(&hobi);
        assert_eq!(q.offer(&hobi, &by(1), stop(3)), Err(Unqueued::TaskerFull));
        assert_eq!(q.pending(&hobi), before);
        for n in 3..9u8 {
            q.offer(&hobi, &by(u32::from(n) + 10), stop(n)).unwrap();
        }
        let full = q.pending(&hobi);
        assert_eq!(q.offer(&hobi, &by(99), stop(99)), Err(Unqueued::AgentFull));
        assert_eq!(q.pending(&hobi), full);
    }

    #[test]
    fn the_same_task_is_queued_once() {
        let mut q = NoticeQueue::new();
        let hobi = agent("hobi");
        let again = Notice {
            id: NoticeId([42; 16]),
            ..stop(1)
        };
        assert_eq!(q.offer(&hobi, &by(1), stop(1)), Ok(()));
        assert_eq!(q.offer(&hobi, &by(1), again), Ok(()));
        assert_eq!(q.pending(&hobi), vec![stop(1)]);
        let other_task = Notice {
            task: Some(TaskId([43; 16])),
            ..stop(1)
        };
        assert_eq!(q.offer(&hobi, &by(1), other_task.clone()), Ok(()));
        assert_eq!(q.pending(&hobi), vec![stop(1), other_task]);
    }

    #[test]
    fn a_repeat_is_accepted_though_the_tasker_is_full() {
        let mut q = NoticeQueue::new();
        let hobi = agent("hobi");
        q.offer(&hobi, &by(1), stop(1)).unwrap();
        q.offer(&hobi, &by(1), stop(2)).unwrap();
        assert_eq!(q.offer(&hobi, &by(1), stop(2)), Ok(()));
        assert_eq!(q.pending(&hobi).len(), 2);
    }

    #[test]
    fn pending_is_offered_until_retired_and_oldest_first() {
        let mut q = NoticeQueue::new();
        let hobi = agent("hobi");
        q.offer(&hobi, &by(1), stop(5)).unwrap();
        q.offer(&hobi, &by(2), stop(3)).unwrap();
        let want = vec![NoticeId([5; 16]), NoticeId([3; 16])];
        assert_eq!(ids(&q, &hobi), want);
        assert_eq!(ids(&q, &hobi), want);
        assert!(q.pending(&agent("jin")).is_empty());
    }

    #[test]
    fn retire_removes_only_what_it_selects_for_that_agent() {
        let mut q = NoticeQueue::new();
        let (hobi, jin) = (agent("hobi"), agent("jin"));
        q.offer(&hobi, &by(1), stop(1)).unwrap();
        q.offer(&hobi, &by(2), stop(2)).unwrap();
        q.offer(&jin, &by(1), stop(1)).unwrap();
        q.retire(&hobi, |n| n.id == NoticeId([1; 16]));
        assert_eq!(ids(&q, &hobi), vec![NoticeId([2; 16])]);
        assert_eq!(ids(&q, &jin), vec![NoticeId([1; 16])]);
        assert_eq!(
            q.offer(&hobi, &by(1), stop(3)),
            Ok(()),
            "a retired notice frees its tasker's room"
        );
        assert_eq!(q.agents().collect::<Vec<_>>(), [&hobi, &jin]);
        q.retire(&jin, |_| true);
        assert_eq!(
            q.agents().collect::<Vec<_>>(),
            [&hobi],
            "an agent with no notice left is not listed"
        );
    }

    #[test]
    fn retire_all_empties_one_agent_only() {
        let mut q = NoticeQueue::new();
        let (hobi, jin) = (agent("hobi"), agent("jin"));
        q.offer(&hobi, &by(1), stop(1)).unwrap();
        q.offer(&hobi, &by(2), stop(2)).unwrap();
        q.offer(&jin, &by(1), stop(1)).unwrap();
        q.retire_all(&hobi);
        assert!(q.pending(&hobi).is_empty());
        assert_eq!(ids(&q, &jin), vec![NoticeId([1; 16])]);
        assert_eq!(q.agents().collect::<Vec<_>>(), [&jin]);
    }
}
