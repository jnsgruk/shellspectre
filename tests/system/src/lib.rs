pub mod event;
pub mod fixture;
pub mod harness;
pub mod shspectr;
pub mod ssh;
pub mod vm;

use vm::TestVm;

/// RAII guard that destroys a `TestVm` on drop.
///
/// Used by the smoke test to validate VM provisioning independently of the
/// shared fixture.
pub struct VmGuard(Option<TestVm>);

impl VmGuard {
    pub fn new(vm: TestVm) -> Self {
        Self(Some(vm))
    }

    pub fn vm(&self) -> &TestVm {
        match self.0.as_ref() {
            Some(vm) => vm,
            None => panic!("vm guard should contain vm"),
        }
    }
}

impl Drop for VmGuard {
    fn drop(&mut self) {
        if let Some(vm) = self.0.as_mut() {
            let _ = vm.destroy();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vm_guard_wraps_and_unwraps_value() {
        let vm = TestVm::provision().expect("provision vm");
        let name = vm.name.clone();

        let guard = VmGuard::new(vm);
        assert_eq!(guard.vm().name, name);
    }
}
