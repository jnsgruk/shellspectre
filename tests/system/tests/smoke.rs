use anyhow::Result;
use shspectr_system_tests::{VmGuard, ssh, vm::TestVm};

/// Validates VM provisioning and SSH connectivity independently of the
/// shared fixture. This test provisions its own VM to exercise and verify
/// the provisioning code path itself.
#[tokio::test]
async fn smoke_provision_ssh_teardown() -> Result<()> {
    let vm = VmGuard::new(TestVm::provision()?);

    let session = ssh::connect(&vm.vm().ip, &vm.vm().private_key_path).await?;
    let output = ssh::exec(&session, "whoami").await?;
    assert_eq!(output.trim(), "root");

    session.close().await?;

    Ok(())
}
