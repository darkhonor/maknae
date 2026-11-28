//! The halt a control notice sends the task driver: a `Stop` for the task it is
//! working, or a refused poll. It reaches only a wait in progress and never latches.
use maknae_proto::TaskId;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex, PoisonError};
use std::task::{Context, Poll, Waker};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Halt {
    Stop,
    Refused,
}

#[derive(Default)]
struct State {
    seq: u64,
    registered: u64,
    task: Option<TaskId>,
    fired: Option<Halt>,
    waker: Option<Waker>,
}

type Shared = Arc<Mutex<State>>;

fn lock(shared: &Shared) -> std::sync::MutexGuard<'_, State> {
    // Every critical section writes whole fields and never panics midway.
    shared.lock().unwrap_or_else(PoisonError::into_inner)
}

pub fn halts() -> (HaltSender, Halts) {
    let shared = Shared::default();
    (HaltSender(Arc::clone(&shared)), Halts(shared))
}

#[derive(Clone)]
pub struct HaltSender(Shared);

impl HaltSender {
    /// Taken before the poll is sent; a halt it carries reaches only a wait registered by then.
    pub fn mark(&self) -> u64 {
        lock(&self.0).seq
    }

    pub fn stop(&self, task: TaskId, mark: u64) -> bool {
        self.fire(Some(task), Halt::Stop, mark)
    }

    pub fn refused(&self, mark: u64) -> bool {
        self.fire(None, Halt::Refused, mark)
    }

    fn fire(&self, only: Option<TaskId>, halt: Halt, mark: u64) -> bool {
        let waker = {
            let mut s = lock(&self.0);
            let Some(task) = s.task else {
                return false;
            };
            if s.registered > mark || s.fired.is_some() || only.is_some_and(|t| t != task) {
                return false;
            }
            s.fired = Some(halt);
            s.waker.take()
        };
        if let Some(waker) = waker {
            waker.wake();
        }
        true
    }
}

pub struct Halts(Shared);

impl Halts {
    pub fn until(&self, task: TaskId) -> Until<'_> {
        let mut s = lock(&self.0);
        s.seq += 1;
        s.registered = s.seq;
        s.task = Some(task);
        s.fired = None;
        s.waker = None;
        Until {
            halts: self,
            seq: s.seq,
        }
    }
}

pub struct Until<'a> {
    halts: &'a Halts,
    seq: u64,
}

impl Future for Until<'_> {
    type Output = Halt;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Halt> {
        let mut s = lock(&self.halts.0);
        if s.registered != self.seq {
            return Poll::Pending;
        }
        match s.fired.take() {
            Some(halt) => {
                s.task = None;
                Poll::Ready(halt)
            }
            None => {
                s.waker = Some(cx.waker().clone());
                Poll::Pending
            }
        }
    }
}

impl Drop for Until<'_> {
    fn drop(&mut self) {
        let mut s = lock(&self.halts.0);
        if s.registered == self.seq {
            s.task = None;
            s.fired = None;
            s.waker = None;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(n: u8) -> TaskId {
        TaskId([n; 16])
    }

    fn pending(w: &mut Until<'_>) -> bool {
        let mut cx = Context::from_waker(Waker::noop());
        Pin::new(w).poll(&mut cx).is_pending()
    }

    #[tokio::test]
    async fn a_stop_for_the_worked_task_fires_its_wait() {
        let (sender, halts) = halts();
        let mut w = halts.until(id(1));
        assert!(pending(&mut w));
        assert!(sender.stop(id(1), sender.mark()));
        assert_eq!(w.await, Halt::Stop);
    }

    #[test]
    fn a_stop_for_another_task_halts_nothing() {
        let (sender, halts) = halts();
        let mut w = halts.until(id(1));
        assert!(!sender.stop(id(2), sender.mark()));
        assert!(pending(&mut w));
        assert!(sender.stop(id(1), sender.mark()));
        assert!(!pending(&mut w));
    }

    #[tokio::test]
    async fn a_refused_poll_fires_whatever_is_worked() {
        for n in [1, 7] {
            let (sender, halts) = halts();
            let mut w = halts.until(id(n));
            assert!(pending(&mut w));
            assert!(sender.refused(sender.mark()));
            assert_eq!(w.await, Halt::Refused);
        }
    }

    #[test]
    fn a_halt_with_no_wait_in_progress_is_dropped_and_never_latches() {
        let (sender, halts) = halts();
        assert!(!sender.refused(sender.mark()));
        assert!(!sender.stop(id(1), sender.mark()));
        let mut w = halts.until(id(1));
        assert!(pending(&mut w));
        assert!(sender.stop(id(1), sender.mark()));
        assert!(!pending(&mut w));
    }

    #[test]
    fn a_dropped_wait_unregisters() {
        let (sender, halts) = halts();
        let w = halts.until(id(1));
        drop(w);
        assert!(!sender.stop(id(1), sender.mark()));
        assert!(!sender.refused(sender.mark()));
    }

    #[test]
    fn a_stop_read_by_a_poll_sent_before_the_wait_is_ignored() {
        let (sender, halts) = halts();
        let m = sender.mark();
        let mut w = halts.until(id(1));
        assert!(!sender.stop(id(1), m));
        assert!(!sender.refused(m));
        assert!(pending(&mut w));
        assert!(sender.stop(id(1), sender.mark()));
        assert!(!pending(&mut w));
    }

    #[test]
    fn a_fired_wait_dropped_unpolled_leaves_nothing_behind() {
        let (sender, halts) = halts();
        let w = halts.until(id(1));
        assert!(sender.stop(id(1), sender.mark()));
        drop(w);
        let mut w = halts.until(id(1));
        assert!(pending(&mut w));
    }

    #[tokio::test]
    async fn a_stop_after_until_but_before_the_first_poll_is_taken() {
        let (sender, halts) = halts();
        let w = halts.until(id(1));
        assert!(sender.stop(id(1), sender.mark()));
        assert_eq!(w.await, Halt::Stop);
    }

    #[test]
    fn a_fired_wait_takes_no_second_halt_and_keeps_the_first() {
        let (sender, halts) = halts();
        let mut w = halts.until(id(1));
        assert!(sender.stop(id(1), sender.mark()));
        assert!(!sender.refused(sender.mark()));
        let mut cx = Context::from_waker(Waker::noop());
        assert_eq!(Pin::new(&mut w).poll(&mut cx), Poll::Ready(Halt::Stop));
        assert!(!sender.stop(id(1), sender.mark()));
    }

    #[test]
    fn each_wait_advances_the_mark() {
        let (sender, halts) = halts();
        let before = sender.mark();
        let w = halts.until(id(1));
        assert_eq!(sender.mark(), before + 1);
        drop(w);
        let _w = halts.until(id(1));
        assert_eq!(sender.mark(), before + 2);
    }

    #[test]
    fn a_wait_replaced_by_a_newer_one_neither_fires_nor_unregisters_it() {
        let (sender, halts) = halts();
        let old = halts.until(id(1));
        let mut new = halts.until(id(2));
        assert!(!sender.stop(id(1), sender.mark()));
        drop(old);
        assert!(sender.stop(id(2), sender.mark()));
        assert!(!pending(&mut new));
    }

    #[tokio::test]
    async fn a_halt_wakes_a_waiting_task() {
        let (sender, halts) = halts();
        let halts = Arc::new(halts);
        let h = Arc::clone(&halts);
        let (ready, registered) = tokio::sync::oneshot::channel();
        let waiter = tokio::spawn(async move {
            let w = h.until(id(1));
            ready.send(()).unwrap();
            w.await
        });
        registered.await.unwrap();
        tokio::task::yield_now().await;
        assert!(sender.refused(sender.mark()));
        let got = tokio::time::timeout(std::time::Duration::from_secs(5), waiter)
            .await
            .expect("the halt did not wake its wait")
            .unwrap();
        assert_eq!(got, Halt::Refused);
    }

    #[test]
    fn until_is_send() {
        fn assert_send<T: Send>(_: &T) {}
        let (_, halts) = halts();
        assert_send(&halts.until(id(1)));
    }
}
