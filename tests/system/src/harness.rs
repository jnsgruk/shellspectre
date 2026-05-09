use anyhow::Result;
use openssh::Session;

use crate::event::{self, Event};
use crate::vm::TestVm;
use crate::{fixture, shspectr, ssh};

/// A test harness that provides access to the shared VM and SSH session.
///
/// Encapsulates the common setup that every system test needs:
/// shared VM connection, SSH session, and the start/exercise/stop/collect
/// workflow.
pub struct TestHarness {
    pub session: Session,
    ip: String,
    private_key_path: String,
}

impl TestHarness {
    /// Create a new harness backed by the shared test VM.
    ///
    /// On first call, the shared VM is provisioned and shspectr is installed.
    /// Subsequent calls reuse the same VM.
    pub async fn new() -> Result<Self> {
        let conn = fixture::vm_connection_info();
        let session = ssh::connect(&conn.ip, &conn.private_key_path).await?;
        Ok(Self {
            session,
            ip: conn.ip,
            private_key_path: conn.private_key_path,
        })
    }

    /// Start shspectr, run the exercise, stop, and return parsed events.
    pub async fn capture(
        &self,
        extra_args: &str,
        exercise: impl AsyncExercise,
    ) -> Result<Vec<Event>> {
        let pid = shspectr::start_with_args(&self.session, extra_args).await?;
        exercise.run().await?;
        let lines = shspectr::stop_and_collect(&self.session, &pid).await?;
        Ok(event::parse_events(&lines))
    }

    /// Start shspectr with default args, run the exercise, stop, and return
    /// parsed events.
    pub async fn capture_default(&self, exercise: impl AsyncExercise) -> Result<Vec<Event>> {
        self.capture("", exercise).await
    }

    /// Start shspectr with extra args and return the raw JSONL lines.
    ///
    /// Use this for tests that need the raw output (e.g. SQLite sink tests
    /// that don't parse JSONL).
    pub async fn start(&self, extra_args: &str) -> Result<String> {
        shspectr::start_with_args(&self.session, extra_args).await
    }

    /// Stop shspectr and return raw JSONL lines.
    pub async fn stop_and_collect(&self, pid: &str) -> Result<Vec<String>> {
        shspectr::stop_and_collect(&self.session, pid).await
    }

    /// Execute a command over SSH.
    pub async fn exec(&self, cmd: &str) -> Result<String> {
        ssh::exec(&self.session, cmd).await
    }

    /// Execute a command with a PTY via the system SSH client.
    pub async fn exec_with_pty(&self, cmd: &str) -> Result<String> {
        ssh::exec_with_pty(&self.ip, &self.private_key_path, cmd).await
    }

    /// Run a function with access to the shared `TestVm`.
    #[allow(clippy::unused_self)]
    pub fn with_vm<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&TestVm) -> R,
    {
        fixture::with_vm(f)
    }

    /// Close the SSH session.
    pub async fn close(self) -> Result<()> {
        self.session.close().await?;
        Ok(())
    }
}

/// Trait for async exercise closures passed to `capture()`.
///
/// Auto-implemented for `async FnOnce() -> Result<()>` via blanket impl.
pub trait AsyncExercise {
    fn run(self) -> impl Future<Output = Result<()>> + Send;
}

impl<F, Fut> AsyncExercise for F
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = Result<()>> + Send,
{
    fn run(self) -> impl Future<Output = Result<()>> + Send {
        self()
    }
}
