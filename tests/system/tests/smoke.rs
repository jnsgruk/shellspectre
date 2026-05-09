use anyhow::Result;
use oxilog_system_tests::{ssh, vm::TestVm};

#[tokio::test]
async fn smoke_provision_ssh_teardown() -> Result<()> {
    let mut vm = TestVm::provision()?;

    let session = ssh::connect(&vm.ip, &vm.private_key_path).await?;
    let output = ssh::exec(&session, "whoami").await?;
    assert_eq!(output.trim(), "root");

    session.close().await?;
    vm.destroy()?;

    Ok(())
}
