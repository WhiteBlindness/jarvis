//! In-memory coordination between the RPC server, the worker session and
//! the supervisor. Nothing here is a source of truth: decisions and state
//! live in the store, and these are only signals to look again.

use std::sync::{Arc, Mutex, MutexGuard};

use jarvis_protocol::{WorkerState, WorkerView};
use jarvis_sandbox::Contained;
use tokio::sync::{Notify, watch};

use crate::approval::ApprovalBroker;

#[derive(Debug)]
pub struct Hub {
    /// Wakes a session waiting on an approval.
    pub approvals: ApprovalBroker,
    /// Wakes the session when a job is queued.
    pub jobs: Notify,
    /// Bumped whenever a job or approval changes, for long-polling clients.
    changes: watch::Sender<u64>,
    worker: Mutex<WorkerView>,
    contained: Mutex<Option<Arc<Contained>>>,
    /// Who asked the Core to stop, when a client did.
    stop_reason: Mutex<Option<String>>,
}

impl Default for Hub {
    fn default() -> Self {
        Self {
            approvals: ApprovalBroker::default(),
            jobs: Notify::new(),
            changes: watch::Sender::new(0),
            worker: Mutex::new(WorkerView {
                state: WorkerState::Starting,
                pid: None,
                restarts: 0,
                containment: String::new(),
            }),
            contained: Mutex::new(None),
            stop_reason: Mutex::new(None),
        }
    }
}

impl Hub {
    pub fn changed(&self) {
        self.changes
            .send_modify(|version| *version = version.wrapping_add(1));
    }

    pub fn subscribe(&self) -> watch::Receiver<u64> {
        self.changes.subscribe()
    }

    pub fn worker(&self) -> WorkerView {
        lock(&self.worker).clone()
    }

    pub fn update_worker(&self, update: impl FnOnce(&mut WorkerView)) {
        update(&mut lock(&self.worker));
    }

    pub fn set_worker_state(&self, state: WorkerState) {
        self.update_worker(|worker| worker.state = state);
    }

    pub fn set_contained(&self, contained: Option<Arc<Contained>>) {
        *lock(&self.contained) = contained;
    }

    pub fn set_stop_reason(&self, reason: String) {
        *lock(&self.stop_reason) = Some(reason);
    }

    pub fn stop_reason(&self) -> Option<String> {
        lock(&self.stop_reason).clone()
    }

    /// Whether `pid` belongs to the running worker or a process it started.
    pub fn is_worker_process(&self, pid: u32) -> bool {
        lock(&self.contained)
            .as_ref()
            .is_some_and(|contained| contained.contains(pid))
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|poison| poison.into_inner())
}
