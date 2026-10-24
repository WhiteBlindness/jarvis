//! The gaming governor (ADR 0016): the loop that reads the process list and
//! decides, and the gate that sessions read before they claim a job.
//!
//! The loop tests use a scripted source and Tokio's paused clock, so the
//! timing assertions are exact. The gate tests drive a real session over
//! in-memory pipes, as `resume.rs` does, against a hub whose governor status
//! the test sets directly or through a real `Governor`.

use std::collections::{BTreeMap, VecDeque};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use jarvis_core::config::{GovernorConfig, Limits};
use jarvis_core::gateway::Gateway;
use jarvis_core::governor::{
    ActivityError, ActivitySource, Governor, Reading, ReadingFuture, Status,
};
use jarvis_core::hub::Hub;
use jarvis_core::policy::Policy;
use jarvis_core::session::{SessionContext, SessionEnd, SessionError, SessionReport, run_session};
use jarvis_core::store::Store;
use jarvis_protocol::{
    AuditEventKind, Capability, CoreMessage, Goal, GovernorPhase, GovernorReason, JobId, JobStatus,
    PolicyDecision, decode_core_message,
};
use jarvis_tools::{FixtureRoot, Toolbox, WorkspaceRoot};
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, DuplexStream, Lines};
use tokio::sync::{Semaphore, watch};
use tokio::task::JoinHandle;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

// --- a scripted source --------------------------------------------------------------------------

/// Answers with the next scripted reading, then repeats the last one. It
/// never goes through `spawn_blocking`, so paused time stays exact.
#[derive(Debug)]
struct Scripted {
    queue: Mutex<VecDeque<Reading>>,
    current: Mutex<Reading>,
    reads: AtomicUsize,
    at: Mutex<Vec<Instant>>,
    /// When set, a read first waits for a permit: the first detection is
    /// still pending until the test adds one.
    gate: Option<Arc<Semaphore>>,
}

impl Scripted {
    fn script(readings: Vec<Reading>) -> Arc<Self> {
        let last = readings.last().cloned().unwrap_or(Ok(None));
        Arc::new(Self {
            queue: Mutex::new(readings.into()),
            current: Mutex::new(last),
            reads: AtomicUsize::new(0),
            at: Mutex::new(Vec::new()),
            gate: None,
        })
    }

    fn blocked(then: Reading) -> (Arc<Self>, Arc<Semaphore>) {
        let gate = Arc::new(Semaphore::new(0));
        let source = Arc::new(Self {
            queue: Mutex::new(VecDeque::from([then.clone()])),
            current: Mutex::new(then),
            reads: AtomicUsize::new(0),
            at: Mutex::new(Vec::new()),
            gate: Some(Arc::clone(&gate)),
        });
        (source, gate)
    }

    fn reads(&self) -> usize {
        self.reads.load(Ordering::SeqCst)
    }

    /// Wait until the governor has started its `count`th read. A read starts
    /// only after the previous one has been applied, recorded and published,
    /// so this says how many readings were fully handled, whatever the speed
    /// of the database. The paused clock cannot say it.
    async fn handled(&self, count: usize) {
        within_real(10, "the governor's readings", async {
            while self.reads() < count {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        })
        .await;
    }
}

impl ActivitySource for Scripted {
    fn read(&self) -> ReadingFuture<'_> {
        Box::pin(async move {
            if let Some(gate) = &self.gate {
                gate.acquire().await.unwrap().forget();
            }
            self.reads.fetch_add(1, Ordering::SeqCst);
            self.at.lock().unwrap().push(Instant::now());
            let mut current = self.current.lock().unwrap();
            if let Some(next) = self.queue.lock().unwrap().pop_front() {
                *current = next;
            }
            current.clone()
        })
    }
}

fn game() -> Reading {
    Ok(Some("cs2.exe".to_owned()))
}

fn clear() -> Reading {
    Ok(None)
}

fn broken() -> Reading {
    Err(ActivityError("the process list is unavailable".into()))
}

/// The first read says the list is clear. The second does not finish until
/// the test sends its answer. Later reads repeat that answer.
#[derive(Debug)]
struct Stalling {
    reads: AtomicUsize,
    answer: Mutex<Option<tokio::sync::oneshot::Receiver<Reading>>>,
    last: Mutex<Reading>,
}

impl Stalling {
    fn new() -> (Arc<Self>, tokio::sync::oneshot::Sender<Reading>) {
        let (send, receive) = tokio::sync::oneshot::channel();
        let source = Arc::new(Self {
            reads: AtomicUsize::new(0),
            answer: Mutex::new(Some(receive)),
            last: Mutex::new(clear()),
        });
        (source, send)
    }

    fn reads(&self) -> usize {
        self.reads.load(Ordering::SeqCst)
    }
}

impl ActivitySource for Stalling {
    fn read(&self) -> ReadingFuture<'_> {
        Box::pin(async move {
            let number = self.reads.fetch_add(1, Ordering::SeqCst);
            if number == 1 {
                let receive = self.answer.lock().unwrap().take().unwrap();
                let answer = receive.await.unwrap_or_else(|_| broken());
                *self.last.lock().unwrap() = answer;
            }
            self.last.lock().unwrap().clone()
        })
    }
}

/// Reads fine once, then panics inside `read`.
#[derive(Debug)]
struct Panicking(AtomicUsize);

impl ActivitySource for Panicking {
    fn read(&self) -> ReadingFuture<'_> {
        Box::pin(async move {
            if self.0.fetch_add(1, Ordering::SeqCst) > 0 {
                panic!("the source broke");
            }
            clear()
        })
    }
}

/// What `tracing` printed, per thread. One subscriber is installed for the
/// whole test binary, because a per-test subscriber races with the other
/// tests over `tracing`'s global cache of which callsites are enabled. Each
/// test runs the governor on its own thread, so it reads only its own lines.
#[derive(Clone, Default)]
struct Captured(Arc<Mutex<std::collections::HashMap<std::thread::ThreadId, String>>>);

impl Captured {
    /// The shared capture, installing the subscriber on first use.
    fn install() -> Self {
        static CAPTURE: std::sync::OnceLock<Captured> = std::sync::OnceLock::new();
        CAPTURE
            .get_or_init(|| {
                let captured = Captured::default();
                tracing::subscriber::set_global_default(
                    tracing_subscriber::fmt()
                        .with_writer(captured.clone())
                        .with_ansi(false)
                        .finish(),
                )
                .expect("no other subscriber in this test binary");
                captured
            })
            .clone()
    }

    /// Lines this thread logged that contain `text`.
    fn lines_with(&self, text: &str) -> usize {
        let all = self.0.lock().unwrap();
        all.get(&std::thread::current().id()).map_or(0, |logged| {
            logged.lines().filter(|l| l.contains(text)).count()
        })
    }
}

impl std::io::Write for Captured {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0
            .lock()
            .unwrap()
            .entry(std::thread::current().id())
            .or_default()
            .push_str(&String::from_utf8_lossy(bytes));
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Captured {
    type Writer = Captured;

    fn make_writer(&'a self) -> Captured {
        self.clone()
    }
}

/// Fails the test if `future` takes more than `seconds` of real time. The
/// paused clock cannot do this: it can jump ahead while the Core waits for
/// its blocking threads, which would make a slow machine look like a hang.
async fn within_real<T>(
    seconds: u64,
    what: &str,
    future: impl std::future::Future<Output = T>,
) -> T {
    let (send, expired) = tokio::sync::oneshot::channel();
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_secs(seconds));
        let _ = send.send(());
    });
    tokio::select! {
        value = future => value,
        _ = expired => panic!("timed out after {seconds} s of real time: {what}"),
    }
}

// --- the loop -----------------------------------------------------------------------------------

fn settings(poll_ms: u64, resume_ms: u64, alert_ms: u64) -> GovernorConfig {
    GovernorConfig {
        enabled: true,
        processes: vec!["cs2.exe".to_owned()],
        poll: Duration::from_millis(poll_ms),
        resume_delay: Duration::from_millis(resume_ms),
        alert_after: Duration::from_millis(alert_ms),
    }
}

struct Rig {
    dir: tempfile::TempDir,
    store: Store,
    hub: Arc<Hub>,
    status: watch::Receiver<Status>,
    stop: CancellationToken,
    task: JoinHandle<()>,
    started: Instant,
}

impl Rig {
    fn start(source: Arc<impl ActivitySource>, config: &GovernorConfig) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("jarvis.db")).unwrap();
        let hub = Arc::new(Hub::default());
        let governor = Governor::new(config, store.clone(), Arc::clone(&hub), source);
        let status = hub.subscribe_governor();
        let stop = CancellationToken::new();
        let task = tokio::spawn(governor.run(stop.clone()));
        Self {
            dir,
            store,
            hub,
            status,
            stop,
            task,
            started: Instant::now(),
        }
    }

    async fn reaches(&mut self, phase: GovernorPhase) -> Status {
        let wait = self.status.wait_for(|status| status.phase == phase);
        within_real(10, &format!("the governor reaching {phase:?}"), wait)
            .await
            .unwrap()
            .clone()
    }

    async fn holds_for(&mut self, reason: GovernorReason) -> Status {
        let wait = self.status.wait_for(|status| status.reason == Some(reason));
        within_real(10, &format!("a hold for {reason:?}"), wait)
            .await
            .unwrap()
            .clone()
    }

    /// Time since the governor started, in whole milliseconds.
    fn elapsed_ms(&self) -> u128 {
        self.started.elapsed().as_millis()
    }

    fn audit(&self) -> Vec<AuditEventKind> {
        self.store
            .audit_events(None, 1000)
            .unwrap()
            .into_iter()
            .map(|event| event.event)
            .filter(|event| event.name().starts_with("governor_"))
            .collect()
    }

    /// Wait until at least `count` governor events are on the record. A hold
    /// closes the gate first and is written after.
    async fn recorded(&self, count: usize) {
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while self.audit().len() < count {
            assert!(
                std::time::Instant::now() < deadline,
                "the events were never recorded"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    /// Run SQL on a second connection to the Core's database.
    fn sql(&self, text: &str) {
        let conn = rusqlite::Connection::open(self.dir.path().join("jarvis.db")).unwrap();
        conn.busy_timeout(Duration::from_secs(5)).unwrap();
        conn.execute_batch(text).unwrap();
    }

    async fn stop(self) {
        self.stop.cancel();
        self.task.await.unwrap();
    }
}

fn hold_game() -> AuditEventKind {
    AuditEventKind::GovernorHold {
        reason: GovernorReason::Game,
        process: Some("cs2.exe".to_owned()),
    }
}

fn hold_failed() -> AuditEventKind {
    AuditEventKind::GovernorHold {
        reason: GovernorReason::DetectionFailed,
        process: None,
    }
}

#[tokio::test(start_paused = true)]
async fn until_the_first_reading_the_gate_is_closed_and_nothing_is_recorded() {
    let (source, _gate) = Scripted::blocked(clear());
    let config = settings(1_000, 3_000, 86_400_000);
    let rig = Rig::start(source, &config);
    let status = rig.hub.governor_status();
    assert_eq!(status.phase, GovernorPhase::Held);
    assert_eq!(status.reason, Some(GovernorReason::Starting));
    assert!(!status.is_open());
    assert!(rig.audit().is_empty());
    rig.stop().await;
}

#[tokio::test(start_paused = true)]
async fn a_clear_first_reading_opens_the_gate_with_no_delay_and_no_event() {
    let config = settings(1_000, 30_000, 86_400_000);
    let mut rig = Rig::start(Scripted::script(vec![clear()]), &config);
    rig.reaches(GovernorPhase::Open).await;
    assert_eq!(rig.elapsed_ms(), 0, "no resume delay at start-up");
    assert!(
        rig.audit().is_empty(),
        "nothing was held, so nothing to record"
    );
    rig.stop().await;
}

#[tokio::test(start_paused = true)]
async fn the_gate_opens_after_exactly_the_resume_delay_and_the_release_is_recorded_first() {
    let config = settings(1_000, 3_000, 86_400_000);
    let source = Scripted::script(vec![game(), game(), clear()]);
    let mut rig = Rig::start(Arc::clone(&source), &config);

    let held = rig.holds_for(GovernorReason::Game).await;
    assert_eq!(held.process.as_deref(), Some("cs2.exe"));
    rig.recorded(1).await;
    assert_eq!(rig.audit(), [hold_game()]);

    // The game is gone at the third reading (2 s). The delay runs from there.
    let releasing = rig.reaches(GovernorPhase::Releasing).await;
    assert!(!releasing.is_open());
    assert_eq!(rig.elapsed_ms(), 2_000);

    rig.reaches(GovernorPhase::Open).await;
    assert_eq!(rig.elapsed_ms(), 5_000, "2 s plus the 3 s delay");
    // The gate is open, so the event that says so must already be written.
    assert_eq!(
        rig.audit(),
        [
            hold_game(),
            AuditEventKind::GovernorReleased { held_ms: 5_000 }
        ]
    );
    rig.stop().await;
}

#[tokio::test(start_paused = true)]
async fn a_game_that_comes_back_during_the_delay_restarts_it() {
    let config = settings(1_000, 3_000, 86_400_000);
    // game, clear, clear, game, clear, clear, clear, clear ...
    let source = Scripted::script(vec![game(), clear(), clear(), game(), clear()]);
    let mut rig = Rig::start(source, &config);
    rig.reaches(GovernorPhase::Releasing).await;
    rig.reaches(GovernorPhase::Held).await;
    assert_eq!(rig.elapsed_ms(), 3_000);
    rig.reaches(GovernorPhase::Releasing).await;
    assert_eq!(rig.elapsed_ms(), 4_000);
    rig.reaches(GovernorPhase::Open).await;
    assert_eq!(rig.elapsed_ms(), 7_000);
    assert_eq!(
        rig.audit(),
        [
            hold_game(),
            AuditEventKind::GovernorReleased { held_ms: 7_000 }
        ],
        "one hold, one release: the interruption is not a new hold"
    );
    rig.stop().await;
}

#[tokio::test(start_paused = true)]
async fn a_long_hold_raises_one_alert_and_is_never_released_by_time() {
    let config = settings(1_000, 3_000, 5_000);
    let source = Scripted::script(vec![game()]);
    let mut rig = Rig::start(Arc::clone(&source), &config);

    let wait = rig.status.wait_for(|status| status.overdue);
    let status = within_real(10, "the alert", wait).await.unwrap().clone();
    assert_eq!(status.phase, GovernorPhase::Held);
    assert_eq!(rig.elapsed_ms(), 5_000);
    rig.recorded(2).await;
    assert_eq!(
        rig.audit(),
        [
            hold_game(),
            AuditEventKind::GovernorHoldOverdue { held_ms: 5_000 }
        ]
    );

    // A long time later: still held, still one alert.
    tokio::time::sleep(Duration::from_secs(3_600)).await;
    assert_eq!(rig.hub.governor_status().phase, GovernorPhase::Held);
    assert!(!rig.hub.governor_status().is_open());
    assert_eq!(rig.audit().len(), 2);
    let view = rig.hub.governor_status().view(Instant::now());
    assert!(view.overdue);
    assert!(view.held_ms.unwrap() >= 3_600_000);
    rig.stop().await;
}

#[tokio::test(start_paused = true)]
async fn a_failed_detection_holds_and_a_streak_is_recorded_once() {
    let config = settings(1_000, 3_000, 86_400_000);
    let source = Scripted::script(vec![broken(), broken(), broken(), broken(), clear()]);
    let mut rig = Rig::start(Arc::clone(&source), &config);

    let held = rig.holds_for(GovernorReason::DetectionFailed).await;
    assert_eq!(held.process, None);
    rig.reaches(GovernorPhase::Releasing).await;
    assert_eq!(source.reads(), 5, "the streak lasted four readings");
    assert_eq!(
        rig.audit(),
        [hold_failed()],
        "one event for the whole streak"
    );
    rig.reaches(GovernorPhase::Open).await;
    assert_eq!(
        rig.audit(),
        [
            hold_failed(),
            AuditEventKind::GovernorReleased { held_ms: 7_000 }
        ]
    );
    rig.stop().await;
}

#[tokio::test(start_paused = true)]
async fn if_the_release_cannot_be_recorded_the_gate_stays_closed_until_it_can() {
    let config = settings(1_000, 2_000, 86_400_000);
    let source = Scripted::script(vec![game(), clear()]);
    let mut rig = Rig::start(Arc::clone(&source), &config);
    rig.sql(
        "CREATE TRIGGER no_release BEFORE INSERT ON audit_events
         WHEN NEW.kind = 'governor_released'
         BEGIN SELECT RAISE(ABORT, 'audit unavailable'); END;",
    );
    rig.reaches(GovernorPhase::Releasing).await;

    // Many readings later the delay is long over, but the gate is shut.
    source.handled(40).await;
    let status = rig.hub.governor_status();
    assert_eq!(status.phase, GovernorPhase::Releasing);
    assert!(!status.is_open());
    assert_eq!(rig.audit(), [hold_game()]);

    rig.sql("DROP TRIGGER no_release");
    rig.reaches(GovernorPhase::Open).await;
    let audit = rig.audit();
    assert_eq!(audit.len(), 2);
    assert!(matches!(
        audit[1],
        AuditEventKind::GovernorReleased { held_ms } if held_ms >= 30_000
    ));
    rig.stop().await;
}

#[tokio::test(start_paused = true)]
async fn a_hold_applies_even_if_it_cannot_be_recorded() {
    let config = settings(1_000, 2_000, 86_400_000);
    let mut rig = Rig::start(Scripted::script(vec![clear(), game()]), &config);
    rig.sql(
        "CREATE TRIGGER no_hold BEFORE INSERT ON audit_events
         WHEN NEW.kind = 'governor_hold'
         BEGIN SELECT RAISE(ABORT, 'audit unavailable'); END;",
    );
    rig.reaches(GovernorPhase::Open).await;
    let held = rig.reaches(GovernorPhase::Held).await;
    assert_eq!(held.reason, Some(GovernorReason::Game));
    assert!(!rig.hub.governor_status().is_open(), "jobs are held anyway");
    assert!(rig.audit().is_empty());
    rig.stop().await;
}

#[tokio::test(start_paused = true)]
async fn the_task_ends_when_the_core_shuts_down() {
    let config = settings(1_000, 2_000, 86_400_000);
    let mut rig = Rig::start(Scripted::script(vec![game()]), &config);
    rig.reaches(GovernorPhase::Held).await;
    within_real(10, "the governor stopping", rig.stop()).await;
}

#[tokio::test(start_paused = true)]
async fn a_game_closes_the_gate_before_the_hold_is_recorded() {
    let config = settings(1_000, 2_000, 86_400_000);
    let mut rig = Rig::start(Scripted::script(vec![clear(), game()]), &config);
    rig.reaches(GovernorPhase::Open).await;

    // Another connection holds the write lock on the database, so the hold
    // cannot be written until it lets go (the Core waits up to 5 s for it).
    let lock = rusqlite::Connection::open(rig.dir.path().join("jarvis.db")).unwrap();
    lock.execute_batch("BEGIN IMMEDIATE").unwrap();
    let locked_at = std::time::Instant::now();

    rig.holds_for(GovernorReason::Game).await;
    assert!(!rig.hub.governor_status().is_open());
    assert!(
        locked_at.elapsed() < Duration::from_secs(2),
        "the gate waited for the audit write"
    );
    assert!(rig.audit().is_empty(), "the hold is not on the record yet");

    // Once the database is free the hold is recorded after all.
    lock.execute_batch("ROLLBACK").unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while rig.audit().is_empty() {
        assert!(
            std::time::Instant::now() < deadline,
            "the hold was never recorded"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(rig.audit(), [hold_game()]);
    rig.stop().await;
}

#[tokio::test(start_paused = true)]
async fn a_read_that_never_finishes_holds_the_jobs_and_is_not_started_again() {
    let config = settings(1_000, 2_000, 86_400_000);
    let (source, _never_answered) = Stalling::new();
    let mut rig = Rig::start(Arc::clone(&source), &config);
    rig.reaches(GovernorPhase::Open).await;

    rig.holds_for(GovernorReason::DetectionFailed).await;
    assert_eq!(rig.elapsed_ms(), 2_000, "one poll after the read began");
    assert!(!rig.hub.governor_status().is_open());

    rig.recorded(1).await;
    tokio::time::sleep(Duration::from_secs(60)).await;
    assert_eq!(source.reads(), 2, "no second read while one is in flight");
    assert_eq!(rig.hub.governor_status().phase, GovernorPhase::Held);
    assert_eq!(rig.audit(), [hold_failed()], "one streak, one event");
    // The governor can still stop with the read outstanding.
    within_real(10, "stopping with a read outstanding", rig.stop()).await;
}

#[tokio::test(start_paused = true)]
async fn a_late_answer_to_the_one_read_in_flight_is_used() {
    let config = settings(1_000, 2_000, 86_400_000);
    let (source, answer) = Stalling::new();
    let mut rig = Rig::start(Arc::clone(&source), &config);
    rig.holds_for(GovernorReason::DetectionFailed).await;
    assert_eq!(source.reads(), 2);

    answer.send(game()).unwrap();
    let held = rig.holds_for(GovernorReason::Game).await;
    assert_eq!(held.process.as_deref(), Some("cs2.exe"));
    assert_eq!(source.reads(), 2, "the late answer came from the same read");

    // After it, reads go on every poll again.
    while source.reads() < 4 {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    rig.stop().await;
}

#[tokio::test(start_paused = true)]
async fn if_the_governor_task_dies_the_gate_is_closed() {
    let config = settings(1_000, 2_000, 86_400_000);
    let mut rig = Rig::start(Arc::new(Panicking(AtomicUsize::new(0))), &config);
    rig.reaches(GovernorPhase::Open).await;

    let outcome = (&mut rig.task).await;
    assert!(outcome.is_err_and(|error| error.is_panic()));
    let status = rig.hub.governor_status();
    assert_eq!(status.phase, GovernorPhase::Held);
    assert_eq!(status.reason, Some(GovernorReason::DetectionFailed));
    assert!(!status.is_open());
}

#[tokio::test(start_paused = true)]
async fn a_task_that_is_stopped_leaves_the_gate_as_it_was() {
    let config = settings(1_000, 2_000, 86_400_000);
    let mut rig = Rig::start(Scripted::script(vec![clear()]), &config);
    rig.reaches(GovernorPhase::Open).await;
    let hub = Arc::clone(&rig.hub);
    rig.stop().await;
    assert_eq!(hub.governor_status().phase, GovernorPhase::Open);
}

#[tokio::test(start_paused = true)]
async fn a_release_that_cannot_be_recorded_is_logged_once_per_streak() {
    let captured = Captured::install();
    let config = settings(1_000, 2_000, 86_400_000);
    let source = Scripted::script(vec![game(), clear()]);
    let mut rig = Rig::start(Arc::clone(&source), &config);
    rig.sql(
        "CREATE TRIGGER no_release BEFORE INSERT ON audit_events
         WHEN NEW.kind = 'governor_released'
         BEGIN SELECT RAISE(ABORT, 'audit unavailable'); END;",
    );
    rig.reaches(GovernorPhase::Releasing).await;
    // The release is attempted at the readings from 3 s on; by the 12th
    // reading it has failed several times.
    source.handled(12).await;
    assert_eq!(
        captured.lines_with("could not record a governor event"),
        1,
        "one line for the whole streak"
    );
    let status = rig.hub.governor_status();
    assert_eq!(status.phase, GovernorPhase::Releasing);
    assert!(!status.is_open());

    rig.sql("DROP TRIGGER no_release");
    rig.reaches(GovernorPhase::Open).await;
    rig.stop().await;
}

#[tokio::test(start_paused = true)]
async fn with_no_resume_delay_a_release_that_cannot_be_recorded_shows_as_releasing() {
    let config = settings(1_000, 0, 86_400_000);
    let source = Scripted::script(vec![game(), clear()]);
    let mut rig = Rig::start(Arc::clone(&source), &config);
    rig.sql(
        "CREATE TRIGGER no_release BEFORE INSERT ON audit_events
         WHEN NEW.kind = 'governor_released'
         BEGIN SELECT RAISE(ABORT, 'audit unavailable'); END;",
    );

    // The game is gone, so health must not say it still runs; the gate stays
    // shut because the release is not on the record.
    let status = rig.reaches(GovernorPhase::Releasing).await;
    assert_eq!((status.reason, status.process), (None, None));
    source.handled(6).await;
    let status = rig.hub.governor_status();
    assert_eq!(status.phase, GovernorPhase::Releasing);
    assert!(!status.is_open());
    assert_eq!(rig.audit(), [hold_game()]);

    rig.sql("DROP TRIGGER no_release");
    rig.reaches(GovernorPhase::Open).await;
    let audit = rig.audit();
    assert_eq!(audit.len(), 2);
    assert!(matches!(audit[1], AuditEventKind::GovernorReleased { .. }));
    rig.stop().await;
}

/// Make the audit log refuse events of `kind`.
fn refuse(rig: &Rig, kind: &str) {
    rig.sql(&format!(
        "CREATE TRIGGER refuse_{kind} BEFORE INSERT ON audit_events
         WHEN NEW.kind = '{kind}'
         BEGIN SELECT RAISE(ABORT, 'audit unavailable'); END;"
    ));
}

fn accept(rig: &Rig, kind: &str) {
    rig.sql(&format!("DROP TRIGGER refuse_{kind}"));
}

fn overdue(held_ms: u64) -> AuditEventKind {
    AuditEventKind::GovernorHoldOverdue { held_ms }
}

#[tokio::test(start_paused = true)]
async fn an_alert_that_could_not_be_recorded_is_recorded_once_when_the_database_recovers() {
    let config = settings(1_000, 2_000, 5_000);
    let source = Scripted::script(vec![game()]);
    let mut rig = Rig::start(Arc::clone(&source), &config);
    refuse(&rig, "governor_hold_overdue");

    let status = within_real(10, "the alert", rig.status.wait_for(|s| s.overdue))
        .await
        .unwrap()
        .clone();
    assert_eq!(status.phase, GovernorPhase::Held, "the alert is published");
    rig.recorded(1).await;
    source.handled(15).await;
    assert_eq!(rig.audit(), [hold_game()], "the alert is not on the record");

    accept(&rig, "governor_hold_overdue");
    rig.recorded(2).await;
    // Many readings later it is still there once, and nothing else came.
    source.handled(source.reads() + 8).await;
    assert_eq!(rig.audit(), [hold_game(), overdue(5_000)]);
    assert!(!rig.hub.governor_status().is_open());
    rig.stop().await;
}

#[tokio::test(start_paused = true)]
async fn a_hold_that_could_not_be_recorded_is_recorded_once_when_the_database_recovers() {
    let config = settings(1_000, 2_000, 86_400_000);
    let source = Scripted::script(vec![clear(), game()]);
    let mut rig = Rig::start(Arc::clone(&source), &config);
    refuse(&rig, "governor_hold");

    rig.holds_for(GovernorReason::Game).await;
    source.handled(10).await;
    assert!(rig.audit().is_empty());
    assert!(
        !rig.hub.governor_status().is_open(),
        "the gate closed anyway"
    );

    accept(&rig, "governor_hold");
    rig.recorded(1).await;
    source.handled(source.reads() + 8).await;
    assert_eq!(rig.audit(), [hold_game()]);
    rig.stop().await;
}

#[tokio::test(start_paused = true)]
async fn events_that_were_never_recorded_are_reported_when_the_core_stops() {
    let captured = Captured::install();
    let config = settings(1_000, 2_000, 86_400_000);
    let source = Scripted::script(vec![clear(), game()]);
    let mut rig = Rig::start(Arc::clone(&source), &config);
    refuse(&rig, "governor_hold");

    rig.holds_for(GovernorReason::Game).await;
    source.handled(6).await;
    assert!(rig.audit().is_empty());
    assert_eq!(captured.lines_with("were never recorded"), 0);

    rig.stop().await;
    assert_eq!(
        captured.lines_with("were never recorded"),
        1,
        "one line when the task ends"
    );
}

#[tokio::test(start_paused = true)]
async fn nothing_is_reported_at_shutdown_when_every_event_was_recorded() {
    let captured = Captured::install();
    let config = settings(1_000, 2_000, 86_400_000);
    let source = Scripted::script(vec![clear(), game()]);
    let mut rig = Rig::start(Arc::clone(&source), &config);

    rig.holds_for(GovernorReason::Game).await;
    rig.recorded(1).await;
    rig.stop().await;
    assert_eq!(captured.lines_with("were never recorded"), 0);
}

#[tokio::test(start_paused = true)]
async fn a_release_waits_for_every_event_before_it_to_be_recorded() {
    let config = settings(1_000, 2_000, 3_000);
    // The game runs past the alert time and then leaves.
    let mut readings = vec![game(); 5];
    readings.push(clear());
    let source = Scripted::script(readings);
    let mut rig = Rig::start(Arc::clone(&source), &config);
    refuse(&rig, "governor_hold_overdue");

    rig.reaches(GovernorPhase::Releasing).await;
    source.handled(20).await;
    let status = rig.hub.governor_status();
    assert_eq!(status.phase, GovernorPhase::Releasing);
    assert!(
        !status.is_open(),
        "the release must not pass the missing alert"
    );
    assert_eq!(rig.audit(), [hold_game()]);

    accept(&rig, "governor_hold_overdue");
    rig.reaches(GovernorPhase::Open).await;
    // The gate is open, so everything before it is on the record, in order.
    let audit = rig.audit();
    assert_eq!(audit.len(), 3, "{audit:?}");
    assert_eq!(audit[0], hold_game());
    assert_eq!(audit[1], overdue(3_000));
    assert!(matches!(audit[2], AuditEventKind::GovernorReleased { .. }));
    source.handled(source.reads() + 5).await;
    assert_eq!(rig.audit().len(), 3, "nothing is written twice");
    rig.stop().await;
}

#[tokio::test(start_paused = true)]
async fn an_alert_and_a_release_due_on_the_same_reading_keep_the_gate_shut_until_both_are_recorded()
{
    // The game leaves at 1 s, so the release is due at 3 s: the same reading
    // at which the hold reaches the alert time.
    let config = settings(1_000, 2_000, 3_000);
    let source = Scripted::script(vec![game(), clear()]);
    let mut rig = Rig::start(Arc::clone(&source), &config);
    refuse(&rig, "governor_released");

    let status = within_real(10, "the alert", rig.status.wait_for(|s| s.overdue))
        .await
        .unwrap()
        .clone();
    assert_eq!(status.phase, GovernorPhase::Releasing);
    assert_eq!(rig.elapsed_ms(), 3_000);
    rig.recorded(2).await;
    source.handled(source.reads() + 6).await;
    let status = rig.hub.governor_status();
    assert_eq!(status.phase, GovernorPhase::Releasing);
    assert!(status.overdue);
    assert!(!status.is_open());
    assert_eq!(
        rig.audit(),
        [hold_game(), overdue(3_000)],
        "the alert is on the record and the release is not"
    );

    accept(&rig, "governor_released");
    rig.reaches(GovernorPhase::Open).await;
    let audit = rig.audit();
    assert_eq!(audit.len(), 3, "{audit:?}");
    assert_eq!(audit[0], hold_game());
    assert_eq!(audit[1], overdue(3_000));
    assert!(matches!(audit[2], AuditEventKind::GovernorReleased { .. }));
    source.handled(source.reads() + 5).await;
    assert_eq!(rig.audit().len(), 3, "the alert is recorded once");
    rig.stop().await;
}

#[tokio::test(start_paused = true)]
async fn a_hold_and_an_alert_that_wait_together_are_recorded_in_order() {
    let config = settings(1_000, 2_000, 3_000);
    let source = Scripted::script(vec![game()]);
    let mut rig = Rig::start(Arc::clone(&source), &config);
    refuse(&rig, "governor_hold");
    refuse(&rig, "governor_hold_overdue");

    within_real(10, "the alert", rig.status.wait_for(|s| s.overdue))
        .await
        .unwrap();
    source.handled(12).await;
    assert!(rig.audit().is_empty());

    // Only the alert is accepted at first: it must still wait for the hold.
    accept(&rig, "governor_hold_overdue");
    source.handled(source.reads() + 4).await;
    assert!(rig.audit().is_empty(), "the alert may not pass the hold");

    accept(&rig, "governor_hold");
    rig.recorded(2).await;
    source.handled(source.reads() + 4).await;
    assert_eq!(rig.audit(), [hold_game(), overdue(3_000)]);
    rig.stop().await;
}

// --- the gate -----------------------------------------------------------------------------------

struct Env {
    dir: tempfile::TempDir,
    store: Store,
    hub: Arc<Hub>,
}

impl Env {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("fixtures")).unwrap();
        std::fs::create_dir_all(dir.path().join("workspace")).unwrap();
        let store = Store::open(&dir.path().join("jarvis.db")).unwrap();
        Self {
            dir,
            store,
            hub: Arc::new(Hub::default()),
        }
    }

    fn submit(&self, goal: &str) -> JobId {
        let goal = Goal::try_from(goal.to_owned()).unwrap();
        self.store.submit_job(&goal, "test client").unwrap().job_id
    }

    fn job(&self, job: JobId) -> (JobStatus, u32) {
        let record = self.store.job(job).unwrap().unwrap();
        (record.status, record.attempts)
    }

    /// Hold jobs for a game, as the governor would.
    fn hold(&self) {
        let origin = Instant::now();
        let state = jarvis_core::governor::machine::State::Held {
            since: 0,
            hold: jarvis_core::governor::machine::Hold::Game("cs2.exe".into()),
            overdue: false,
        };
        self.hub.set_governor(Status::of(&state, origin));
    }

    fn open(&self) {
        let state = jarvis_core::governor::machine::State::Open;
        self.hub.set_governor(Status::of(&state, Instant::now()));
    }

    /// A session on this database and hub, with the handshake done.
    async fn session(&self) -> Harness {
        self.session_with_timeout(Duration::from_secs(120)).await
    }

    async fn session_with_timeout(&self, job_timeout: Duration) -> Harness {
        let limits = Limits {
            tool_timeout: Duration::from_secs(10),
            ..Limits::default()
        };
        let toolbox = Toolbox::new(
            "test",
            FixtureRoot::open(&self.dir.path().join("fixtures"), 1024).unwrap(),
            WorkspaceRoot::open(&self.dir.path().join("workspace"), 1024).unwrap(),
        );
        let policy: BTreeMap<_, _> = [(Capability::SystemInfo, PolicyDecision::Allow)]
            .into_iter()
            .collect();
        let ctx = SessionContext {
            store: self.store.clone(),
            policy: Policy::new(policy),
            gateway: Gateway::new(
                Arc::new(toolbox),
                limits.tool_timeout,
                limits.max_result_bytes(),
            ),
            limits,
            handshake_timeout: Duration::from_secs(10),
            approval_ttl: Duration::from_secs(60),
            job_timeout,
            core_version: "test",
            hub: Arc::clone(&self.hub),
            session_agent: None,
        };
        let (to_core, core_reader) = tokio::io::duplex(1 << 20);
        let (core_writer, from_core) = tokio::io::duplex(1 << 20);
        let shutdown = CancellationToken::new();
        let token = shutdown.clone();
        let session =
            tokio::spawn(async move { run_session(&ctx, core_reader, core_writer, &token).await });
        let mut harness = Harness {
            shutdown,
            to_core: Some(to_core),
            from_core: BufReader::new(from_core).lines(),
            session,
        };
        harness
            .send(json!({"protocol": 3, "type": "hello", "worker": "test", "worker_version": "1"}))
            .await;
        assert!(matches!(harness.recv().await, CoreMessage::Welcome(_)));
        harness
    }
}

struct Harness {
    shutdown: CancellationToken,
    to_core: Option<DuplexStream>,
    from_core: Lines<BufReader<DuplexStream>>,
    session: JoinHandle<Result<SessionReport, SessionError>>,
}

impl Harness {
    async fn send(&mut self, value: Value) {
        let pipe = self.to_core.as_mut().unwrap();
        pipe.write_all(&serde_json::to_vec(&value).unwrap())
            .await
            .unwrap();
        pipe.write_all(b"\n").await.unwrap();
    }

    async fn recv(&mut self) -> CoreMessage {
        let line = self
            .from_core
            .next_line()
            .await
            .unwrap()
            .expect("the Core closed the stream");
        decode_core_message(line.as_bytes()).expect("the Core sent an invalid frame")
    }

    /// Whether the Core sends anything within `wait`.
    async fn stays_quiet_for(&mut self, wait: Duration) -> bool {
        tokio::time::timeout(wait, self.from_core.next_line())
            .await
            .is_err()
    }

    async fn takes(&mut self, job: JobId) {
        let message = within_real(10, "the job being handed out", self.recv()).await;
        match message {
            CoreMessage::Job(assigned) => assert_eq!(assigned.job_id, job),
            other => panic!("expected a job, got {other:?}"),
        }
    }

    async fn completes(&mut self, job: JobId) {
        self.send(json!({"protocol": 3, "type": "job_result", "job_id": job,
                         "outcome": "completed", "summary": "done"}))
            .await;
    }

    async fn worker_exits(mut self) -> SessionReport {
        self.to_core.take();
        self.ended().await
    }

    async fn ended(self) -> SessionReport {
        within_real(10, "the session ending", self.session)
            .await
            .unwrap()
            .unwrap()
    }
}

const QUIET: Duration = Duration::from_millis(300);

#[tokio::test]
async fn while_held_a_queued_job_is_not_claimed() {
    let env = Env::new();
    env.hold();
    let job = env.submit("wait for the game");
    let mut h = env.session().await;

    assert!(h.stays_quiet_for(QUIET).await, "no job reached the worker");
    assert_eq!(
        env.job(job),
        (JobStatus::Queued, 0),
        "no attempt was counted"
    );
    let started = env
        .store
        .audit_events(None, 100)
        .unwrap()
        .into_iter()
        .any(|event| event.event.name() == "job_started");
    assert!(!started);

    // A wake-up for a new job does not get past the gate either.
    env.hub.jobs.notify_one();
    assert!(h.stays_quiet_for(QUIET).await);
    assert_eq!(env.job(job), (JobStatus::Queued, 0));

    h.worker_exits().await;
}

#[tokio::test]
async fn releasing_the_gate_wakes_an_idle_session_by_itself() {
    let env = Env::new();
    env.hold();
    // Queued through the store: nothing tells the session about it.
    let job = env.submit("wait for the game");
    let mut h = env.session().await;
    assert!(h.stays_quiet_for(QUIET).await);

    env.open();
    h.takes(job).await;
    assert_eq!(env.job(job), (JobStatus::Running, 1));
    h.completes(job).await;
    let report = h.worker_exits().await;
    assert_eq!(report.end, SessionEnd::WorkerClosed);
    assert_eq!(env.job(job).0, JobStatus::Completed);
}

#[tokio::test(start_paused = true)]
async fn a_hold_longer_than_the_job_timeout_does_not_use_up_the_job() {
    let env = Env::new();
    env.hold();
    let job = env.submit("wait for the game");
    let mut h = env.session_with_timeout(Duration::from_secs(120)).await;

    // Five job timeouts pass while the game runs.
    tokio::time::sleep(Duration::from_secs(600)).await;
    assert_eq!(env.job(job), (JobStatus::Queued, 0));

    env.open();
    h.takes(job).await;
    // The clock for the job starts now, not when it was queued or held.
    tokio::time::sleep(Duration::from_secs(100)).await;
    h.completes(job).await;
    let report = h.worker_exits().await;
    assert_eq!(report.end, SessionEnd::WorkerClosed, "not JobTimedOut");
    assert_eq!(env.job(job), (JobStatus::Completed, 1));
}

#[tokio::test]
async fn a_requeued_job_is_held_too() {
    let env = Env::new();
    env.open();
    let job = env.submit("two attempts");
    let mut first = env.session().await;
    first.takes(job).await;
    first.worker_exits().await;
    assert_eq!(
        env.job(job),
        (JobStatus::Queued, 1),
        "requeued after the worker left"
    );

    env.hold();
    let mut second = env.session().await;
    assert!(second.stays_quiet_for(QUIET).await);
    assert_eq!(env.job(job), (JobStatus::Queued, 1));

    env.open();
    second.takes(job).await;
    assert_eq!(env.job(job), (JobStatus::Running, 2));
    second.completes(job).await;
    second.worker_exits().await;
}

#[tokio::test]
async fn a_hold_that_starts_while_a_job_runs_leaves_it_running() {
    let env = Env::new();
    env.open();
    let job = env.submit("already under way");
    let next = env.submit("queued behind it");
    let mut h = env.session().await;
    h.takes(job).await;

    env.hold();
    h.send(
        json!({"protocol": 3, "type": "tool_request", "request_id": "r1",
                  "job_id": job, "tool": "system.info", "args": {}}),
    )
    .await;
    match h.recv().await {
        CoreMessage::ToolResponse(response) => {
            assert_eq!(response.request_id.as_str(), "r1");
        }
        other => panic!("expected a tool_response, got {other:?}"),
    }
    h.completes(job).await;
    assert!(h.stays_quiet_for(QUIET).await, "the next job waits");
    assert_eq!(env.job(job).0, JobStatus::Completed);
    assert_eq!(env.job(next), (JobStatus::Queued, 0));
    h.worker_exits().await;
}

#[tokio::test]
async fn a_disabled_governor_never_holds_anything() {
    let env = Env::new();
    assert_eq!(env.hub.governor_status(), Status::OFF);
    let job = env.submit("no governor");
    let mut h = env.session().await;
    h.takes(job).await;
    h.completes(job).await;
    h.worker_exits().await;
}

#[tokio::test]
async fn no_job_starts_before_the_first_detection() {
    let env = Env::new();
    let job = env.submit("queued before the Core restarted");
    let (source, first_reading) = Scripted::blocked(clear());
    let config = settings(10, 0, 86_400_000);
    let governor = Governor::new(
        &config,
        env.store.clone(),
        Arc::clone(&env.hub),
        source.clone(),
    );
    let stop = CancellationToken::new();
    let task = tokio::spawn(governor.run(stop.clone()));
    let mut h = env.session().await;

    assert!(
        h.stays_quiet_for(QUIET).await,
        "the first detection is pending"
    );
    assert_eq!(source.reads(), 0);
    assert_eq!(env.job(job), (JobStatus::Queued, 0));

    first_reading.add_permits(1);
    h.takes(job).await;
    assert_eq!(env.job(job), (JobStatus::Running, 1));
    h.completes(job).await;
    stop.cancel();
    task.await.unwrap();
    h.worker_exits().await;
}

#[tokio::test]
async fn a_game_that_is_running_at_start_up_holds_a_job_queued_before_the_restart() {
    let env = Env::new();
    let job = env.submit("queued before the Core restarted");
    let source = Scripted::script(vec![game()]);
    let config = settings(10, 20, 86_400_000);
    let governor = Governor::new(&config, env.store.clone(), Arc::clone(&env.hub), source);
    let stop = CancellationToken::new();
    let task = tokio::spawn(governor.run(stop.clone()));
    let mut h = env.session().await;
    assert!(h.stays_quiet_for(QUIET).await);
    let status = env.hub.governor_status();
    assert_eq!(status.phase, GovernorPhase::Held);
    assert_eq!(status.reason, Some(GovernorReason::Game));
    assert_eq!(env.job(job), (JobStatus::Queued, 0));
    stop.cancel();
    task.await.unwrap();
    h.worker_exits().await;
}

#[tokio::test]
async fn a_held_job_survives_a_restart_unchanged() {
    let env = Env::new();
    env.hold();
    let job = env.submit("wait for the game");
    let h = env.session().await;
    h.shutdown.cancel();
    let report = h.ended().await;
    assert_eq!(report.end, SessionEnd::Shutdown);

    // What the Core does when it starts again.
    env.store.call(|s| s.recover(3)).await.unwrap();
    assert_eq!(env.job(job), (JobStatus::Queued, 0));
}
