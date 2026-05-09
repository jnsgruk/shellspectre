//! OpenTelemetry sink: exports session events as OTLP logs.
//!
//! Events are emitted as structured OTel `LogRecord`s with typed attributes
//! (pid, session_id, command, etc.). I/O event data is truncated to 4 KiB
//! and base64-encoded.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use opentelemetry::KeyValue;
use opentelemetry::logs::{LogRecord as _, Logger, LoggerProvider as _, Severity};
use opentelemetry_otlp::{LogExporter, WithExportConfig};
use opentelemetry_sdk::Resource;
use opentelemetry_sdk::logs::SdkLoggerProvider;
use shspectr_common::EventType;

use crate::event::{ParsedExecEvent, ParsedExitEvent, ParsedIoEvent};
use crate::sink::{SessionInfo, Sink};

/// Maximum bytes of I/O data included in an OTel log record.
const MAX_IO_DATA_BYTES: usize = 4096;

/// Exports session events as OTLP logs to a collector.
pub(crate) struct OtelSink {
    provider: SdkLoggerProvider,
}

impl OtelSink {
    /// Build a new `OtelSink` that exports logs to the given OTLP endpoint.
    pub fn new(endpoint: &str) -> anyhow::Result<Self> {
        let hostname = gethostname();

        let resource = Resource::builder()
            .with_service_name("shspectr")
            .with_attribute(KeyValue::new("host.name", hostname))
            .build();

        let exporter = LogExporter::builder()
            .with_http()
            .with_endpoint(format!("{endpoint}/v1/logs"))
            .build()?;

        let provider = SdkLoggerProvider::builder()
            .with_resource(resource)
            .with_batch_exporter(exporter)
            .build();

        Ok(Self { provider })
    }

    /// Emit a log record with common session attributes already set.
    fn emit_record<F>(&self, session: &SessionInfo<'_>, event_name: &'static str, add_attrs: F)
    where
        F: FnOnce(&mut <opentelemetry_sdk::logs::SdkLogger as Logger>::LogRecord),
    {
        let logger = self.provider.logger("shspectr.events");
        let mut record = logger.create_log_record();
        record.set_severity_number(Severity::Info);
        record.set_body(event_name.into());

        record.add_attribute("session_id", session.session_id.to_string());
        record.add_attribute("session.pid", i64::from(session.pid));
        record.add_attribute("session.comm", session.comm.to_owned());
        record.add_attribute("session.uid", i64::from(session.uid));
        record.add_attribute("session.euid", i64::from(session.euid));
        record.add_attribute("session.tty_nr", i64::from(session.tty_nr));
        record.add_attribute("session.cgroup_id", session.cgroup_id.cast_signed());

        add_attrs(&mut record);

        logger.emit(record);
    }
}

impl Sink for OtelSink {
    fn on_exec(&self, session: &SessionInfo<'_>, event: &ParsedExecEvent) {
        self.emit_record(session, "exec", |record| {
            record.add_attribute("pid", i64::from(event.pid));
            record.add_attribute("ppid", i64::from(event.ppid));
            record.add_attribute("uid", i64::from(event.uid));
            record.add_attribute("gid", i64::from(event.gid));
            record.add_attribute("euid", i64::from(event.euid));
            record.add_attribute("comm", event.comm.clone());
            record.add_attribute("tty_nr", i64::from(event.tty_nr));
            record.add_attribute("cgroup_id", event.cgroup_id.cast_signed());
            record.add_attribute("execution_id", event.execution_id.cast_signed());
            record.add_attribute("filename", event.filename.clone());
            record.add_attribute("argv", event.argv.join(" "));
            record.add_attribute("retval", event.retval);
        });
    }

    fn on_exit(&self, session: &SessionInfo<'_>, event: &ParsedExitEvent, session_complete: bool) {
        self.emit_record(session, "exit", |record| {
            record.add_attribute("pid", i64::from(event.pid));
            record.add_attribute("ppid", i64::from(event.ppid));
            record.add_attribute("uid", i64::from(event.uid));
            record.add_attribute("gid", i64::from(event.gid));
            record.add_attribute("euid", i64::from(event.euid));
            record.add_attribute("comm", event.comm.clone());
            record.add_attribute("tty_nr", i64::from(event.tty_nr));
            record.add_attribute("cgroup_id", event.cgroup_id.cast_signed());
            record.add_attribute("execution_id", event.execution_id.cast_signed());
            record.add_attribute("exit_code", i64::from(event.exit_code));
            record.add_attribute("session_complete", session_complete);
        });
    }

    fn on_io(&self, session: &SessionInfo<'_>, event: &ParsedIoEvent, event_type: EventType) {
        let event_name = match event_type {
            EventType::Read => "read",
            EventType::Write => "write",
            EventType::Exec | EventType::Exit => return,
        };

        self.emit_record(session, event_name, |record| {
            record.add_attribute("pid", i64::from(event.pid));
            record.add_attribute("ppid", i64::from(event.ppid));
            record.add_attribute("uid", i64::from(event.uid));
            record.add_attribute("gid", i64::from(event.gid));
            record.add_attribute("euid", i64::from(event.euid));
            record.add_attribute("comm", event.comm.clone());
            record.add_attribute("tty_nr", i64::from(event.tty_nr));
            record.add_attribute("cgroup_id", event.cgroup_id.cast_signed());
            record.add_attribute("execution_id", event.execution_id.cast_signed());
            record.add_attribute("fd", i64::from(event.fd));
            record.add_attribute("count", event.count.cast_signed());

            let truncated = event.data.len() > MAX_IO_DATA_BYTES;
            let data_slice = &event.data[..event.data.len().min(MAX_IO_DATA_BYTES)];
            record.add_attribute("data_base64", BASE64.encode(data_slice));
            record.add_attribute("data_truncated", truncated);
        });
    }
}

impl Drop for OtelSink {
    fn drop(&mut self) {
        if let Err(err) = self.provider.shutdown() {
            tracing::error!(%err, "OTel log provider shutdown failed");
        }
    }
}

/// Get the system hostname, falling back to "unknown" on error.
fn gethostname() -> String {
    #[allow(clippy::expect_used)] // hostname should always be readable; infallible on Linux
    std::env::var("HOSTNAME")
        .or_else(|_| std::fs::read_to_string("/etc/hostname").map(|s| s.trim().to_owned()))
        .unwrap_or_else(|_| "unknown".to_owned())
}
