use std::sync::{LazyLock, Mutex};

use anyhow::Result;
use openssh::Session;

use crate::vm::TestVm;
use crate::{shspectr, ssh};

/// Shared VM state, provisioned once per test run.
///
/// The `LazyLock` initialises on first access. The `Mutex` ensures
/// single-threaded access (tests already run with `--test-threads=1`,
/// but the mutex prevents accidental races and satisfies `Sync`).
struct SharedState {
    vm: TestVm,
}

static SHARED_VM: LazyLock<Mutex<SharedState>> = LazyLock::new(|| {
    #[allow(clippy::print_stderr)]
    let vm = match TestVm::provision() {
        Ok(vm) => {
            eprintln!("fixture: provisioned shared VM {}", vm.name);
            vm
        }
        Err(e) => panic!("failed to provision shared test VM: {e:#}"),
    };

    // Push files synchronously (lxc file push is a blocking subprocess call).
    vm.push_file(&shspectr::binary_path(), shspectr::REMOTE_BIN)
        .unwrap_or_else(|e| panic!("failed to push shspectr binary: {e:#}"));
    vm.push_file(&shspectr::ebpf_path(), shspectr::REMOTE_EBPF)
        .unwrap_or_else(|e| panic!("failed to push eBPF artifact: {e:#}"));

    // Set permissions via SSH. The LazyLock initialiser may be called from
    // within a tokio runtime (the test harness), so we cannot call `block_on`
    // on the current thread. Spawn a dedicated thread with its own runtime.
    std::thread::spawn({
        let ip = vm.ip.clone();
        let key = vm.private_key_path.clone();
        move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap_or_else(|e| panic!("failed to build tokio runtime for fixture: {e}"));
            rt.block_on(async {
                let session = ssh::connect(&ip, &key)
                    .await
                    .unwrap_or_else(|e| panic!("failed to SSH to shared VM: {e:#}"));
                ssh::exec(
                    &session,
                    &format!(
                        "chmod +x {} && chmod 644 {}",
                        shspectr::REMOTE_BIN,
                        shspectr::REMOTE_EBPF
                    ),
                )
                .await
                .unwrap_or_else(|e| panic!("failed to set permissions: {e:#}"));
                session
                    .close()
                    .await
                    .unwrap_or_else(|e| panic!("failed to close fixture SSH session: {e:#}"));
            });
        }
    })
    .join()
    .unwrap_or_else(|e| panic!("fixture install thread panicked: {e:?}"));

    Mutex::new(SharedState { vm })
});

/// Connection details for the shared test VM.
pub struct VmConnection {
    pub ip: String,
    pub private_key_path: String,
}

/// Get connection details for the shared test VM.
///
/// Provisions and installs shspectr on first call, then returns cached
/// connection info for subsequent calls.
pub fn vm_connection_info() -> VmConnection {
    let state = SHARED_VM
        .lock()
        .unwrap_or_else(|e| panic!("shared VM mutex poisoned: {e}"));
    VmConnection {
        ip: state.vm.ip.clone(),
        private_key_path: state.vm.private_key_path.clone(),
    }
}

/// Run a function with access to the shared `TestVm`.
///
/// Use this for operations that need the VM directly (e.g. `push_file`,
/// `pull_file`).
pub fn with_vm<F, R>(f: F) -> R
where
    F: FnOnce(&TestVm) -> R,
{
    let state = SHARED_VM
        .lock()
        .unwrap_or_else(|e| panic!("shared VM mutex poisoned: {e}"));
    f(&state.vm)
}

/// Create an SSH session to the shared test VM.
pub async fn connect() -> Result<Session> {
    let conn = vm_connection_info();
    ssh::connect(&conn.ip, &conn.private_key_path).await
}
