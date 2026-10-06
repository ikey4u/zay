"""Launcher isolation regressions; no VM, signing, or network is used."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


class DesktopVMTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="zay-desktop-vm-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.scripts = self.root / "client/desktop/scripts"
        self.scripts.mkdir(parents=True)
        shutil.copyfile(Path(__file__).with_name("macos-vm.sh"), self.scripts / "macos-vm.sh")
        be = self.root / "devpane/be"
        be.mkdir(parents=True)
        (be / "check-host.sh").write_text("#!/bin/bash\nexit 0\n")
        (self.scripts / "bundle-macos.sh").write_text(
            '#!/bin/bash\nprintf "bundle %s\\n" "$*" >> "$TEST_LOG"\n'
            'mkdir -p "$TEST_ROOT/client/desktop/dist/Zay Desktop.app"\n')
        self.state = self.root / "devpane/.build/desktop-macos"
        self.state.mkdir(parents=True)
        (self.state / "id_ed25519").write_text("fixture-only")
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.log = self.root / "commands"
        self.env = dict(os.environ, PATH=f"{self.bin}:/usr/bin:/bin",
                        TEST_LOG=str(self.log), TEST_ROOT=str(self.root),
                        APPLE_SIGN_IDENTITY="fixture identity", ZAY_DESKTOP_VM_DNS="alidns")
        self.mock("tart", '''
if [[ "$1" == ip ]]; then
  if [[ "${TEST_COLD_VM:-0}" == 1 && "$2" != --wait && ! -f "$TEST_ROOT/booted" ]]; then exit 1; fi
  echo 192.168.64.42
elif [[ "$1" == run ]]; then touch "$TEST_ROOT/booted"; fi
''')
        self.mock("ssh", '''
if [[ "${TEST_WRONG_GUEST:-0}" == 1 && "${*: -1}" == *'cat /etc/zay-desktop-vm'* ]]; then exit 42; fi
''')
        self.mock("ditto", 'touch "${*: -1}"')
        self.mock("cargo", "exit 0")
        for name in ("open", "scp", "nc"):
            self.mock(name, "exit 0")
        # These programs must never be invoked directly on the host.
        for name in ("sudo", "networksetup", "route", "launchctl"):
            self.mock(name, "exit 99")

    def mock(self, name, body):
        path = self.bin / name
        path.write_text(f'#!/bin/bash\nprintf "{name} %s\\n" "$*" >> "$TEST_LOG"\n' + body + "\n")
        path.chmod(0o755)

    def run_action(self, action="up"):
        self.log.write_text("")
        result = subprocess.run(["/bin/bash", str(self.scripts / "macos-vm.sh"), action],
                                env=self.env, text=True, capture_output=True, timeout=10)
        calls = self.log.read_text()
        for forbidden in ("sudo", "route", "networksetup", "launchctl"):
            self.assertFalse(any(line.startswith(forbidden + " ") for line in calls.splitlines()), calls)
        return result, calls

    def test_missing_signing_identity_stops_before_build_or_vm(self):
        self.env.pop("APPLE_SIGN_IDENTITY")
        result, calls = self.run_action()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("APPLE_SIGN_IDENTITY", result.stderr)
        self.assertEqual(calls, "")

    def test_deploy_and_launch_are_guest_only(self):
        result, calls = self.run_action()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('admin@192.168.64.42 open "/Applications/Zay Desktop.app"', calls)
        self.assertIn("open vnc://admin@192.168.64.42", calls)
        self.assertNotIn("open -n", calls)
        self.assertNotIn("devpane:linux", calls)
        self.assertNotIn(".ssh/id_rsa", calls)
        self.assertIn("cat /etc/zay-desktop-vm", calls)
        self.assertIn("DEVPANE_BIND=127.0.0.1", calls)
        self.assertIn("DEVPANE_DOH=1", calls)
        self.assertIn("networksetup -setdnsservers Ethernet 127.0.0.1", calls)

    def test_default_keeps_inherited_dns(self):
        self.env.pop("ZAY_DESKTOP_VM_DNS")
        result, calls = self.run_action()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("networksetup", calls)
        self.assertNotIn("zay-vm-dns", calls)

    def test_cold_vm_uses_nat_without_host_shares(self):
        self.env["TEST_COLD_VM"] = "1"
        result, calls = self.run_action()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("tart run --no-graphics --no-audio --no-clipboard zay-desktop-macos", calls)
        self.assertNotIn("--net-bridged", calls)
        self.assertNotIn("--dir", calls)

    def test_wrong_guest_marker_blocks_deployment(self):
        self.env["TEST_WRONG_GUEST"] = "1"
        result, calls = self.run_action()
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("scp ", calls)
        self.assertNotIn("open vnc:", calls)

    def test_stop_targets_only_the_desktop_vm(self):
        result, calls = self.run_action("stop")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(calls.strip(), "tart stop zay-desktop-macos")

    def test_reopen_does_not_rebuild_or_launch_on_host(self):
        result, calls = self.run_action("open")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("bundle ", calls)
        self.assertIn("open vnc://admin@192.168.64.42", calls)
        self.assertIn('admin@192.168.64.42 open "/Applications/Zay Desktop.app"', calls)


if __name__ == "__main__":
    unittest.main()
