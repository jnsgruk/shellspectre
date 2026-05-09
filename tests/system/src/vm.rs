use anyhow::{Context, Result, bail};
use rand::Rng;
use std::process::Command;
use std::time::{Duration, Instant};
use tempfile::TempDir;

/// Bump this suffix whenever the base VM provisioning changes.
/// When the expected base isn't found, any existing `shspectr-base-*` VMs
/// are deleted and a new one is created from scratch.
const BASE_VM_NAME: &str = "shspectr-base-c3d5";

/// An LXD VM managed for integration testing.
///
/// On drop, the VM is forcefully deleted. The base VM is never deleted.
pub struct TestVm {
    pub name: String,
    pub ip: String,
    pub key_dir: TempDir,
    pub private_key_path: String,
    destroyed: bool,
}

impl TestVm {
    /// Provision a new test VM by cloning the base VM.
    ///
    /// 1. Ensure the base VM exists (create + provision if not).
    /// 2. Copy the base to a new instance with a random name.
    /// 3. Generate an ephemeral SSH keypair and push it.
    /// 4. Start the VM and wait for SSH.
    pub fn provision() -> Result<Self> {
        Self::ensure_base()?;

        let suffix = random_suffix();
        let name = format!("shspectr-test-{suffix}");

        // Copy base VM to new instance
        lxc(&["copy", BASE_VM_NAME, &name])?;
        lxc(&["start", &name])?;

        // Wait for the VM agent to be ready
        wait_for_agent(&name)?;

        // Generate ephemeral keypair
        let key_dir = TempDir::new().context("create temp dir for SSH keys")?;
        let private_key_path = key_dir.path().join("id_ed25519");
        let private_key_str = private_key_path.to_string_lossy().to_string();

        let status = Command::new("ssh-keygen")
            .args([
                "-t",
                "ed25519",
                "-f",
                &private_key_str,
                "-N",
                "",
                "-q",
                "-C",
                "shspectr-test",
            ])
            .status()
            .context("ssh-keygen")?;
        if !status.success() {
            let _ = lxc(&["delete", &name, "--force"]);
            bail!("ssh-keygen failed");
        }

        let pub_key =
            std::fs::read_to_string(format!("{private_key_str}.pub")).context("read public key")?;

        // Push per-instance SSH key
        let script = format!(
            r"
            mkdir -p /root/.ssh
            chmod 700 /root/.ssh
            echo '{}' >> /root/.ssh/authorized_keys
            chmod 600 /root/.ssh/authorized_keys
            ",
            pub_key.trim()
        );

        if lxc_exec(&name, &script).is_err() {
            let _ = lxc(&["delete", &name, "--force"]);
            bail!("failed to push SSH key to VM {name}");
        }

        let ip = get_ip(&name)?;
        wait_for_ssh(&ip, &private_key_str)?;

        Ok(Self {
            name,
            ip,
            key_dir,
            private_key_path: private_key_str,
            destroyed: false,
        })
    }

    /// Ensure the base VM exists. If the expected base isn't found,
    /// remove any stale `shspectr-base-*` VMs and create a new one.
    #[allow(clippy::print_stderr)]
    fn ensure_base() -> Result<()> {
        if vm_exists(BASE_VM_NAME)? {
            return Ok(());
        }

        // Remove stale base VMs
        let stale = list_vms_matching("shspectr-base-")?;
        for name in &stale {
            eprintln!("removing stale base VM: {name}");
            let _ = lxc(&["delete", name, "--force"]);
        }

        eprintln!("creating base VM: {BASE_VM_NAME}");

        // Launch from upstream image
        lxc(&["launch", "ubuntu:26.04", BASE_VM_NAME, "--vm"])?;
        wait_for_agent(BASE_VM_NAME)?;

        // Provision the base: minimal system with sshd, IPv4 only, fast boot
        let script = r"
            set -e

            # Install sshd
            apt-get update -qq
            apt-get install -y -qq openssh-server >/dev/null 2>&1
            systemctl enable ssh

            # Disable IPv6 system-wide
            cat > /etc/sysctl.d/99-disable-ipv6.conf <<SYSCTL
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
SYSCTL

            # Disable services we don't need for testing
            systemctl disable --now \
                snapd.service snapd.seeded.service snapd.apparmor.service \
                snapd.autoimport.service snapd.core-fixup.service \
                snapd.recovery-chooser-trigger.service snapd.system-shutdown.service \
                cloud-init-local.service cloud-init-main.service \
                cloud-init-network.service cloud-config.service cloud-final.service \
                apport.service \
                ModemManager.service \
                udisks2.service \
                polkit.service \
                networkd-dispatcher.service \
                rsyslog.service \
                chrony.service \
                multipathd.service \
                open-iscsi.service \
                open-vm-tools.service \
                lvm2-monitor.service \
                grub-initrd-fallback.service \
                grub2-common.service \
                secureboot-db.service \
                e2scrub_reap.service \
                pollinate.service \

                console-setup.service \
                keyboard-setup.service \
                setvtrgb.service \
                sysstat.service \
                2>/dev/null || true

            # Remove snapd entirely
            apt-get purge -y -qq snapd >/dev/null 2>&1 || true

            # Set default target to multi-user (no graphical)
            systemctl set-default multi-user.target

            # Clean up
            apt-get autoremove -y -qq >/dev/null 2>&1 || true
            apt-get clean
            rm -rf /var/lib/apt/lists/* /var/cache/snapd /snap
        ";
        lxc_exec(BASE_VM_NAME, script).context("failed to provision base VM")?;

        // Stop the base so it can be copied
        lxc(&["stop", BASE_VM_NAME])?;

        eprintln!("base VM {BASE_VM_NAME} ready");
        Ok(())
    }

    /// Forcefully destroy the VM.
    pub fn destroy(&mut self) -> Result<()> {
        if self.destroyed {
            return Ok(());
        }
        lxc(&["delete", &self.name, "--force"])?;
        self.destroyed = true;
        Ok(())
    }

    /// Push a local file into the VM at the given path.
    pub fn push_file(&self, local: &str, remote: &str) -> Result<()> {
        let dest = format!("{}/{}", self.name, remote.trim_start_matches('/'));
        lxc(&["file", "push", local, &dest])?;
        Ok(())
    }

    /// Pull a file from the VM to a local path.
    pub fn pull_file(&self, remote: &str, local: &str) -> Result<()> {
        let src = format!("{}/{}", self.name, remote.trim_start_matches('/'));
        lxc(&["file", "pull", &src, local])?;
        Ok(())
    }
}

impl Drop for TestVm {
    fn drop(&mut self) {
        if !self.destroyed {
            let _ = lxc(&["delete", &self.name, "--force"]);
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn random_suffix() -> String {
    rand::rng()
        .sample_iter(&rand::distr::Alphanumeric)
        .take(4)
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .concat()
        .chars()
        .take(4)
        .collect()
}

fn lxc(args: &[&str]) -> Result<()> {
    let status = Command::new("lxc")
        .args(args)
        .status()
        .with_context(|| format!("lxc {}", args.join(" ")))?;
    if !status.success() {
        bail!("lxc {} failed", args.join(" "));
    }
    Ok(())
}

fn lxc_exec(vm: &str, script: &str) -> Result<()> {
    let status = Command::new("lxc")
        .args(["exec", vm, "--", "bash", "-c", script])
        .status()
        .with_context(|| format!("lxc exec {vm}"))?;
    if !status.success() {
        bail!("lxc exec {vm} failed");
    }
    Ok(())
}

fn vm_exists(name: &str) -> Result<bool> {
    let output = Command::new("lxc")
        .args(["list", "--format=csv", "-c", "n"])
        .output()
        .context("lxc list")?;
    let text = String::from_utf8_lossy(&output.stdout);
    Ok(text.lines().any(|line| line.trim() == name))
}

fn list_vms_matching(prefix: &str) -> Result<Vec<String>> {
    let output = Command::new("lxc")
        .args(["list", "--format=csv", "-c", "n"])
        .output()
        .context("lxc list")?;
    let text = String::from_utf8_lossy(&output.stdout);
    Ok(text
        .lines()
        .map(|l| l.trim().to_string())
        .filter(|l| l.starts_with(prefix))
        .collect())
}

fn wait_for_agent(name: &str) -> Result<()> {
    let start = Instant::now();
    let timeout = Duration::from_mins(2);
    loop {
        if start.elapsed() > timeout {
            bail!("timed out waiting for VM agent on {name}");
        }
        let output = Command::new("lxc")
            .args(["exec", name, "--", "true"])
            .output()
            .context("lxc exec")?;
        if output.status.success() {
            return Ok(());
        }
        std::thread::sleep(Duration::from_secs(2));
    }
}

fn get_ip(name: &str) -> Result<String> {
    let start = Instant::now();
    let timeout = Duration::from_mins(1);
    loop {
        if start.elapsed() > timeout {
            bail!("timed out waiting for VM IP on {name}");
        }
        let output = Command::new("lxc")
            .args(["list", name, "--format=csv", "-c", "4"])
            .output()
            .context("lxc list")?;
        let text = String::from_utf8_lossy(&output.stdout);
        for line in text.lines() {
            for part in line.split_whitespace() {
                let candidate = part.trim_end_matches(',');
                if candidate.split('.').count() == 4
                    && candidate.split('.').all(|s| s.parse::<u8>().is_ok())
                {
                    return Ok(candidate.to_string());
                }
            }
        }
        std::thread::sleep(Duration::from_secs(2));
    }
}

fn wait_for_ssh(ip: &str, key_path: &str) -> Result<()> {
    let start = Instant::now();
    let timeout = Duration::from_mins(1);
    loop {
        if start.elapsed() > timeout {
            bail!("timed out waiting for SSH on {ip}");
        }
        let status = Command::new("ssh")
            .args([
                "-o",
                "StrictHostKeyChecking=no",
                "-o",
                "UserKnownHostsFile=/dev/null",
                "-o",
                "ConnectTimeout=5",
                "-o",
                "BatchMode=yes",
                "-i",
                key_path,
                &format!("root@{ip}"),
                "true",
            ])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .context("ssh probe")?;
        if status.success() {
            return Ok(());
        }
        std::thread::sleep(Duration::from_secs(2));
    }
}
