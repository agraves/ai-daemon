//! Scheduling and the KV budget (§8).
//!
//! Two scarce things are arbitrated here and they behave completely
//! differently:
//!
//! * **Decode slots.** Few, contended, and latency-critical. Interactive work
//!   preempts background work at a token boundary; within a class, deficit
//!   round-robin means the session that has had the least gets the next slot,
//!   so a chatty client cannot starve a quiet one.
//! * **KV cache.** The real memory pressure. Weights are mmap'd and shared, so
//!   a second session on the same model costs almost nothing until it starts
//!   accumulating context. Under pressure the scheduler drops the least
//!   recently used *background* caches first, tells those clients
//!   `context-evicted`, and lets them replay.
//!
//! VRAM is not cgroup-controllable on any stack we can rely on, so all of this
//! is the daemon's own accounting. That is stated in §14 as a known gap rather
//! than papered over: the numbers here are as good as the backend's estimate
//! of bytes-per-token, and no better.

use std::collections::HashMap;
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use crate::{debug, info};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Class {
    /// A person is watching a cursor blink.
    Interactive,
    /// Indexing, batch embedding, anything with no one waiting.
    Background,
}

impl Class {
    pub fn parse(text: &str) -> Class {
        match text {
            "background" | "batch" => Class::Background,
            _ => Class::Interactive,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Class::Interactive => "interactive",
            Class::Background => "background",
        }
    }
}

/// How the scheduler reaches into a running backend request. Implemented by
/// the backend registry; kept as a trait so the scheduler has no idea what a
/// backend is and cannot be tempted to talk to one directly.
pub trait Preemptor: Send + Sync {
    fn set_paused(&self, backend: &str, req_id: u64, paused: bool);
    fn drop_cache(&self, backend: &str, session: &str);
}

struct Running {
    ticket: u64,
    session: String,
    class: Class,
    backend: Option<String>,
    req_id: Option<u64>,
    paused: bool,
}

struct Waiter {
    ticket: u64,
    session: String,
    class: Class,
}

struct KvEntry {
    bytes: u64,
    class: Class,
    last_used: Instant,
    backend: String,
    /// A session with a request in flight is not a candidate for eviction; we
    /// would be pulling the cache out from under a decode in progress.
    active: bool,
}

struct Inner {
    running: Vec<Running>,
    waiting: Vec<Waiter>,
    /// Tokens served per session, the deficit round-robin counter. Never
    /// reset: absolute service is the fair thing to compare, and u64 of tokens
    /// is not a number any desktop will reach.
    served: HashMap<String, u64>,
    kv: HashMap<String, KvEntry>,
    kv_used: u64,
    next_ticket: u64,
}

pub struct Scheduler {
    inner: Mutex<Inner>,
    slot_free: Condvar,
    max_interactive: u32,
    max_background: u32,
    kv_budget: u64,
    preemptor: Mutex<Option<Arc<dyn Preemptor>>>,
}

/// Held for the duration of one admitted request. Dropping it releases the
/// slot and resumes anything that was preempted, so an early `?` cannot leak a
/// slot and wedge the daemon.
pub struct Slot<'a> {
    scheduler: &'a Scheduler,
    ticket: u64,
}

impl Slot<'_> {
    /// Tell the scheduler which backend request this slot became, so it can be
    /// paused when something more urgent arrives.
    pub fn attach(&self, backend: &str, req_id: u64) {
        let mut inner = self.scheduler.inner.lock().unwrap();
        let should_pause = inner
            .running
            .iter()
            .any(|r| r.class == Class::Interactive && r.ticket != self.ticket);
        let mut pause_now = false;
        if let Some(entry) = inner.running.iter_mut().find(|r| r.ticket == self.ticket) {
            entry.backend = Some(backend.to_string());
            entry.req_id = Some(req_id);
            // A background request that starts while an interactive one is
            // already running starts paused; otherwise it would get a free
            // token before the scheduler noticed it.
            if entry.class == Class::Background && should_pause {
                entry.paused = true;
                pause_now = true;
            }
        }
        drop(inner);
        if pause_now {
            self.scheduler.with_preemptor(|p| p.set_paused(backend, req_id, true));
        }
    }

    pub fn charge(&self, session: &str, tokens: u64) {
        let mut inner = self.scheduler.inner.lock().unwrap();
        *inner.served.entry(session.to_string()).or_insert(0) += tokens;
        if let Some(entry) = inner.kv.get_mut(session) {
            entry.last_used = Instant::now();
        }
    }
}

impl Drop for Slot<'_> {
    fn drop(&mut self) {
        self.scheduler.release(self.ticket);
    }
}

impl Scheduler {
    pub fn new(config: &crate::config::Scheduler) -> Scheduler {
        Scheduler {
            inner: Mutex::new(Inner {
                running: Vec::new(),
                waiting: Vec::new(),
                served: HashMap::new(),
                kv: HashMap::new(),
                kv_used: 0,
                next_ticket: 1,
            }),
            slot_free: Condvar::new(),
            max_interactive: config.max_concurrent_interactive.max(1),
            max_background: config.max_concurrent_background.max(1),
            kv_budget: config.kv_budget_bytes,
            preemptor: Mutex::new(None),
        }
    }

    pub fn set_preemptor(&self, preemptor: Arc<dyn Preemptor>) {
        *self.preemptor.lock().unwrap() = Some(preemptor);
    }

    fn with_preemptor(&self, f: impl FnOnce(&dyn Preemptor)) {
        let guard = self.preemptor.lock().unwrap();
        if let Some(p) = guard.as_ref() {
            f(p.as_ref());
        }
    }

    /// Wait for a decode slot in `class`. Blocks; call from a session thread,
    /// never from the bus thread.
    pub fn admit(&self, session: &str, class: Class) -> Slot<'_> {
        let mut inner = self.inner.lock().unwrap();
        let ticket = inner.next_ticket;
        inner.next_ticket += 1;
        inner.waiting.push(Waiter { ticket, session: session.to_string(), class });

        loop {
            if self.is_turn(&inner, ticket) {
                inner.waiting.retain(|w| w.ticket != ticket);
                inner.running.push(Running {
                    ticket,
                    session: session.to_string(),
                    class,
                    backend: None,
                    req_id: None,
                    paused: false,
                });
                if class == Class::Interactive {
                    let to_pause: Vec<(String, u64)> = inner
                        .running
                        .iter_mut()
                        .filter(|r| r.class == Class::Background && !r.paused)
                        .filter_map(|r| {
                            r.paused = true;
                            Some((r.backend.clone()?, r.req_id?))
                        })
                        .collect();
                    if !to_pause.is_empty() {
                        drop(inner);
                        for (backend, req_id) in &to_pause {
                            debug!("sched: pausing background req {req_id} on {backend}");
                            self.with_preemptor(|p| p.set_paused(backend, *req_id, true));
                        }
                    }
                }
                return Slot { scheduler: self, ticket };
            }
            let (guard, _) = self
                .slot_free
                .wait_timeout(inner, Duration::from_millis(250))
                .unwrap();
            inner = guard;
        }
    }

    /// Whether `ticket` is the waiter that should get the next free slot.
    ///
    /// Interactive first, then least-served — the deficit part of deficit
    /// round-robin. Ties break on ticket order so a client that keeps
    /// re-queuing cannot leapfrog one that has been waiting.
    fn is_turn(&self, inner: &Inner, ticket: u64) -> bool {
        let Some(me) = inner.waiting.iter().find(|w| w.ticket == ticket) else {
            return false;
        };
        let cap = match me.class {
            Class::Interactive => self.max_interactive,
            Class::Background => self.max_background,
        };
        let running_in_class =
            inner.running.iter().filter(|r| r.class == me.class).count() as u32;
        if running_in_class >= cap {
            return false;
        }
        let served_of = |session: &str| inner.served.get(session).copied().unwrap_or(0);
        let my_key = (me.class, served_of(&me.session), me.ticket);
        inner
            .waiting
            .iter()
            .all(|w| (w.class, served_of(&w.session), w.ticket) >= my_key)
    }

    fn release(&self, ticket: u64) {
        let mut inner = self.inner.lock().unwrap();
        inner.running.retain(|r| r.ticket != ticket);
        let interactive_left = inner.running.iter().any(|r| r.class == Class::Interactive);
        let to_resume: Vec<(String, u64)> = if interactive_left {
            Vec::new()
        } else {
            inner
                .running
                .iter_mut()
                .filter(|r| r.paused)
                .filter_map(|r| {
                    r.paused = false;
                    Some((r.backend.clone()?, r.req_id?))
                })
                .collect()
        };
        drop(inner);
        for (backend, req_id) in &to_resume {
            debug!("sched: resuming background req {req_id} on {backend}");
            self.with_preemptor(|p| p.set_paused(backend, *req_id, false));
        }
        self.slot_free.notify_all();
    }

    /// Account for a session's KV cache, evicting others if the budget is
    /// exceeded. Returns the sessions that were evicted so their owners can be
    /// told `context-evicted`.
    pub fn reserve_kv(
        &self,
        session: &str,
        backend: &str,
        class: Class,
        bytes: u64,
    ) -> Result<Vec<String>, String> {
        let mut inner = self.inner.lock().unwrap();
        let previous = inner.kv.get(session).map(|e| e.bytes).unwrap_or(0);
        let mut evicted: Vec<String> = Vec::new();

        if bytes > previous {
            let extra = bytes - previous;
            if extra > self.kv_budget {
                return Err(format!(
                    "{} bytes of context exceeds the whole {} byte KV budget",
                    extra, self.kv_budget
                ));
            }
            // Background caches go first, then idle interactive ones. Nothing
            // with a request in flight is ever evicted, and the requesting
            // session never evicts itself.
            for pass in [Class::Background, Class::Interactive] {
                while inner.kv_used + extra > self.kv_budget {
                    let victim = inner
                        .kv
                        .iter()
                        .filter(|(id, e)| {
                            id.as_str() != session && e.class == pass && !e.active
                        })
                        .min_by_key(|(_, e)| e.last_used)
                        .map(|(id, _)| id.clone());
                    let Some(victim) = victim else { break };
                    let entry = inner.kv.remove(&victim).expect("victim was just found");
                    inner.kv_used = inner.kv_used.saturating_sub(entry.bytes);
                    info!(
                        "sched: evicting {} bytes of {} context for {session}",
                        entry.bytes, victim
                    );
                    evicted.push(victim.clone());
                    let backend = entry.backend.clone();
                    self.with_preemptor(|p| p.drop_cache(&backend, &victim));
                }
            }
            if inner.kv_used + extra > self.kv_budget {
                return Err(format!(
                    "KV budget exhausted: {} of {} bytes in use and nothing evictable",
                    inner.kv_used, self.kv_budget
                ));
            }
            inner.kv_used += extra;
        } else {
            inner.kv_used = inner.kv_used.saturating_sub(previous - bytes);
        }

        inner.kv.insert(
            session.to_string(),
            KvEntry {
                bytes,
                class,
                last_used: Instant::now(),
                backend: backend.to_string(),
                active: true,
            },
        );
        Ok(evicted)
    }

    pub fn mark_idle(&self, session: &str) {
        if let Some(entry) = self.inner.lock().unwrap().kv.get_mut(session) {
            entry.active = false;
            entry.last_used = Instant::now();
        }
    }

    pub fn release_kv(&self, session: &str) {
        let mut inner = self.inner.lock().unwrap();
        if let Some(entry) = inner.kv.remove(session) {
            inner.kv_used = inner.kv_used.saturating_sub(entry.bytes);
        }
    }

    pub fn kv_used(&self) -> (u64, u64) {
        (self.inner.lock().unwrap().kv_used, self.kv_budget)
    }

    pub fn running(&self) -> Vec<(String, &'static str, bool)> {
        self.inner
            .lock()
            .unwrap()
            .running
            .iter()
            .map(|r| (r.session.clone(), r.class.as_str(), r.paused))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc::{channel, Sender};

    struct Recorder(Sender<String>);

    impl Preemptor for Recorder {
        fn set_paused(&self, backend: &str, req_id: u64, paused: bool) {
            let _ = self
                .0
                .send(format!("{} {backend}/{req_id}", if paused { "pause" } else { "resume" }));
        }

        fn drop_cache(&self, backend: &str, session: &str) {
            let _ = self.0.send(format!("drop {backend}/{session}"));
        }
    }

    fn scheduler(kv_budget: u64) -> (Scheduler, std::sync::mpsc::Receiver<String>) {
        let (tx, rx) = channel();
        let scheduler = Scheduler::new(&crate::config::Scheduler {
            kv_budget_bytes: kv_budget,
            max_concurrent_interactive: 2,
            max_concurrent_background: 1,
        });
        scheduler.set_preemptor(Arc::new(Recorder(tx)));
        (scheduler, rx)
    }

    #[test]
    fn an_interactive_request_preempts_a_running_background_one() {
        let (scheduler, events) = scheduler(1 << 30);
        let batch = scheduler.admit("batch", Class::Background);
        batch.attach("mock", 1);
        assert!(events.try_recv().is_err(), "nothing to preempt yet");

        let chat = scheduler.admit("chat", Class::Interactive);
        chat.attach("mock", 2);
        assert_eq!(events.recv().unwrap(), "pause mock/1");

        drop(chat);
        assert_eq!(events.recv().unwrap(), "resume mock/1", "the batch resumes when the user is done");
        drop(batch);
    }

    #[test]
    fn a_background_request_starting_under_interactive_load_starts_paused() {
        let (scheduler, events) = scheduler(1 << 30);
        let chat = scheduler.admit("chat", Class::Interactive);
        chat.attach("mock", 1);

        let batch = scheduler.admit("batch", Class::Background);
        batch.attach("mock", 2);
        assert_eq!(
            events.recv().unwrap(),
            "pause mock/2",
            "otherwise it steals a token before the scheduler notices it"
        );
        drop(batch);
        drop(chat);
    }

    #[test]
    fn the_class_cap_is_respected() {
        let (scheduler, _events) = scheduler(1 << 30);
        std::thread::scope(|scope| {
            let first = scheduler.admit("a", Class::Background);
            assert_eq!(scheduler.running().len(), 1);

            // A second background request must wait: the cap is one.
            let waiter = scope.spawn(|| drop(scheduler.admit("b", Class::Background)));
            std::thread::sleep(Duration::from_millis(200));
            assert_eq!(scheduler.running().len(), 1, "the second one is still queued");
            drop(first);
            waiter.join().unwrap();
        });
    }

    #[test]
    fn kv_pressure_evicts_the_least_recently_used_background_session_first() {
        let (scheduler, events) = scheduler(1000);
        scheduler.reserve_kv("old-batch", "mock", Class::Background, 400).unwrap();
        scheduler.mark_idle("old-batch");
        std::thread::sleep(std::time::Duration::from_millis(5));
        scheduler.reserve_kv("new-batch", "mock", Class::Background, 400).unwrap();
        scheduler.mark_idle("new-batch");
        assert_eq!(scheduler.kv_used().0, 800);

        let evicted = scheduler.reserve_kv("chat", "mock", Class::Interactive, 400).unwrap();
        assert_eq!(evicted, vec!["old-batch"], "the oldest background cache goes first");
        assert_eq!(events.recv().unwrap(), "drop mock/old-batch");
        assert_eq!(scheduler.kv_used().0, 800);
    }

    #[test]
    fn a_session_with_a_request_in_flight_is_never_evicted() {
        let (scheduler, _events) = scheduler(1000);
        // Active, because reserve_kv marks it so and nothing marked it idle.
        scheduler.reserve_kv("busy", "mock", Class::Background, 900).unwrap();
        let error = scheduler
            .reserve_kv("chat", "mock", Class::Interactive, 900)
            .unwrap_err();
        assert!(error.contains("nothing evictable"), "{error}");
    }

    #[test]
    fn a_reservation_larger_than_the_whole_budget_is_refused_outright() {
        let (scheduler, _events) = scheduler(1000);
        let error = scheduler
            .reserve_kv("chat", "mock", Class::Interactive, 2000)
            .unwrap_err();
        assert!(error.contains("exceeds the whole"), "{error}");
    }

    #[test]
    fn releasing_a_session_returns_its_budget() {
        let (scheduler, _events) = scheduler(1000);
        scheduler.reserve_kv("a", "mock", Class::Interactive, 600).unwrap();
        assert_eq!(scheduler.kv_used().0, 600);
        scheduler.release_kv("a");
        assert_eq!(scheduler.kv_used().0, 0);
    }

    #[test]
    fn shrinking_a_reservation_gives_the_difference_back() {
        let (scheduler, _events) = scheduler(1000);
        scheduler.reserve_kv("a", "mock", Class::Interactive, 800).unwrap();
        scheduler.reserve_kv("a", "mock", Class::Interactive, 300).unwrap();
        assert_eq!(scheduler.kv_used().0, 300);
    }
}
