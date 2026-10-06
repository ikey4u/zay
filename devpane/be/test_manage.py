"""Launcher regression checks; no Docker engine or VM is needed."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


class LauncherTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="devpane-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.be = self.root / "devpane" / "be"
        self.be.mkdir(parents=True)
        for name in ("manage.sh", "macos-runtime.sh", "build-linux.sh", "start.sh", "check-host.sh"):
            shutil.copyfile(Path(__file__).parent / name, self.be / name)
        (self.be / "host-proxy.sh").write_text('#!/bin/bash\nprintf "host-proxy %s\\n" "$*" >> "$TEST_LOG"\n')
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.log = self.root / "calls"
        self.env = dict(os.environ, PATH=f"{self.bin}:/usr/bin:/bin",
                        TEST_OS="Darwin", TEST_LOG=str(self.log),
                        COLIMA_HOME=str(self.root / "colima"))
        for key in ("DEVPANE_MACOS_READY", "DEVPANE_BUILD_NETWORK"):
            self.env.pop(key, None)
        self.mock("uname", 'if [[ "$1" == -m ]]; then echo "${TEST_ARCH:-arm64}"; else echo "$TEST_OS"; fi')
        self.mock("sw_vers", 'echo "${TEST_MACOS_VERSION:-26.0}"')
        self.mock("mise", '''
printf 'mise %s\\n' "$*" >> "$TEST_LOG"
if [[ "$4" == devpane:colima-runtime ]]; then exec /bin/bash "$2/devpane/be/macos-runtime.sh" "$6"; fi
''')
        self.mock("colima", '''
printf 'colima %s\\n' "$*" >> "$TEST_LOG"
if [[ "$3" == status ]]; then exit "${TEST_COLIMA_STATUS:-1}"; fi
if [[ "$3" == ssh ]]; then echo "192.168.5.2 STREAM host.lima.internal"; fi
exit "${TEST_COLIMA_START:-0}"
''')
        self.mock("docker", '''
printf 'docker %s|host=%s|context=%s|tls=%s|config=%s|network=%s\\n' \
  "$*" "${DOCKER_HOST:-}" "${DOCKER_CONTEXT:-}" "${DOCKER_TLS_VERIFY:-}" \
  "${DOCKER_CONFIG:-}" "${DEVPANE_BUILD_NETWORK:-}" >> "$TEST_LOG"
if [[ "$1" == network ]]; then echo 172.17.0.1; fi
if [[ "$1" == info && "${2:-}" == --format ]]; then echo aarch64; fi
if [[ "$1" == compose ]]; then exit "${TEST_COMPOSE_EXIT:-0}"; fi
''')
        for name in ("docker-cli-plugin-docker-compose", "docker-cli-plugin-docker-buildx"):
            self.mock(name, "exit 0")

    def mock(self, name, body):
        path = self.bin / name
        path.write_text("#!/bin/bash\nset -eu\n" + body + "\n")
        path.chmod(0o755)

    def run_action(self, action="up", expected=0):
        self.log.write_text("")
        result = subprocess.run(["/bin/bash", str(self.be / "manage.sh"), action],
                                env=self.env, capture_output=True, text=True)
        self.assertEqual(result.returncode, expected, result.stderr)
        return self.log.read_text()

    def test_start_selects_host_default_and_explicit_guest(self):
        (self.be / "macos-pane.sh").write_text(
            '#!/bin/bash\nprintf "macos-pane %s\\n" "$*" >> "$TEST_LOG"\n')
        for host, lab, expected_guest in (("Darwin", "auto", "macos"),
                                         ("Linux", "auto", "linux"),
                                         ("Darwin", "linux", "linux"),
                                         ("Darwin", "macos", "macos")):
            with self.subTest(host=host, lab=lab):
                self.log.write_text("")
                result = subprocess.run(["bash", str(self.be / "start.sh"), lab],
                                        env=dict(self.env, TEST_OS=host), capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                calls = self.log.read_text()
                if expected_guest == "macos":
                    self.assertIn("run devpane:linux", calls)
                    self.assertIn("exec tart@2.40.1 rust@stable protoc@36.2 node@24.19.0 cmake@4.4.3 -- bash", calls)
                    self.assertIn("/devpane/be/macos-vm.sh", calls)
                    self.assertIn("run devpane:macos-serve", calls)
                else:
                    self.assertIn("up -d mesh-peer mesh-echo zay", calls)
                    self.assertNotIn("/devpane/be/macos-vm.sh", calls)

    def test_unsupported_host_rejected_before_side_effects(self):
        for host, arch, version, lab in (("Linux", "arm64", "26", "macos"),
                                        ("Darwin", "x86_64", "26", "auto"),
                                        ("Darwin", "arm64", "12.6", "linux"),
                                        ("FreeBSD", "x86_64", "26", "auto"),
                                        ("Linux", "riscv64", "26", "linux")):
            with self.subTest(host=host, arch=arch, lab=lab):
                self.log.write_text("")
                result = subprocess.run(["bash", str(self.be / "start.sh"), lab],
                                        env=dict(self.env, TEST_OS=host, TEST_ARCH=arch,
                                                 TEST_MACOS_VERSION=version), capture_output=True, text=True)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("host", result.stderr)
                self.assertEqual(self.log.read_text(), "")

    def test_macos_installs_tools_and_starts_isolated_vm(self):
        self.env.update(DOCKER_HOST="tcp://elsewhere:2376", DOCKER_CONTEXT="other",
                        DOCKER_TLS_VERIFY="1", DOCKER_CONFIG="/do/not/change")
        calls = self.run_action()
        self.assertIn("run devpane:colima-runtime -- up", calls)
        self.assertIn("colima --profile zay-devpane start --runtime docker --vm-type vz --activate=false", calls)
        self.assertIn(f"host=unix://{self.env['COLIMA_HOME']}/zay-devpane/docker.sock|context=|tls=", calls)
        self.assertIn("run devpane:host-build", calls)
        self.assertIn("run devpane:linux-build", calls)
        self.assertLess(calls.index("run devpane:linux-build"), calls.index(" build|"))
        self.assertIn("up -d mesh-peer mesh-echo zay", calls)
        self.assertLess(calls.index("host-proxy start"), calls.index("up -d mesh-peer mesh-echo zay"))
        self.assertIn("host-proxy start", calls)
        self.assertIn("network=default", calls)
        for plugin in ("compose", "buildx"):
            link = self.root / "devpane/.build/docker/cli-plugins" / f"docker-{plugin}"
            self.assertEqual(link.resolve(), self.bin / f"docker-cli-plugin-docker-{plugin}")

    def test_linux_binaries_are_cross_compiled_on_host_for_engine_architecture(self):
        include = self.root / "include/google/protobuf"
        include.mkdir(parents=True)
        (include / "duration.proto").write_text("")
        self.mock("protoc", "exit 0")
        self.mock("rustup", 'printf "rustup %s\\n" "$*" >> "$TEST_LOG"')
        self.mock("cargo", '''
printf 'cargo %s\\n' "$*" >> "$TEST_LOG"
while [[ "$1" != --target ]]; do shift; done
triple="${2%.2.28}"
mkdir -p "$CARGO_TARGET_DIR/$triple/debug"
touch "$CARGO_TARGET_DIR/$triple/debug/zay" "$CARGO_TARGET_DIR/$triple/debug/devpane-be"
''')
        for host in ("Darwin", "Linux"):
            for arch, triple, directory in (("aarch64", "aarch64-unknown-linux-gnu", "arm64"),
                                             ("x86_64", "x86_64-unknown-linux-gnu", "amd64")):
                with self.subTest(host=host, arch=arch):
                    self.log.write_text("")
                    env = dict(self.env, TEST_OS=host, DEVPANE_TARGET_ARCH=arch)
                    result = subprocess.run(["bash", str(self.be / "build-linux.sh")],
                                            env=env, capture_output=True, text=True)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    calls = self.log.read_text()
                    self.assertIn(f"rustup target add {triple}", calls)
                    self.assertEqual(calls.count(f"--target {triple}.2.28"), 2)
                    self.assertNotIn("docker", calls)
                    self.assertTrue((self.root / f"devpane/.build/linux/{directory}/zay").is_file())
                    self.assertTrue((self.root / f"devpane/.build/linux/{directory}/devpane-be").is_file())

    def test_running_vm_is_reused(self):
        self.env["TEST_COLIMA_STATUS"] = "0"
        self.assertNotIn(" start ", self.run_action())

    def test_failed_vm_start_stops_before_build(self):
        self.env["TEST_COLIMA_START"] = "42"
        self.assertFalse(any(line.startswith("docker ") for line in
                             self.run_action(expected=42).splitlines()))

    def test_teardown_and_inspection_do_not_start_vm(self):
        for action in ("down", "reset", "logs", "status"):
            with self.subTest(action=action):
                calls = self.run_action(action)
                self.assertNotIn("colima ", calls)
                self.assertIn(f"run devpane:colima-runtime -- {action}", calls)

    def test_linux_uses_existing_engine(self):
        self.env.update(TEST_OS="Linux", DOCKER_HOST="unix:///existing.sock")
        calls = self.run_action()
        self.assertIn("run devpane:host-build", calls)
        self.assertIn("run devpane:linux-build", calls)
        self.assertLess(calls.index("run devpane:linux-build"), calls.index(" build|"))
        self.assertNotIn("run devpane:macos", calls)
        self.assertNotIn("colima ", calls)
        self.assertIn("host=unix:///existing.sock", calls)
        self.assertIn("network=host", calls)

    def test_network_override(self):
        self.env.update(TEST_OS="Linux", DEVPANE_BUILD_NETWORK="default")
        self.assertIn("network=default", self.run_action())

    def test_linux_host_address_override_is_preserved(self):
        self.env.update(TEST_OS="Linux", DEVPANE_HOST_ADDR="172.18.0.1",
                        DEVPANE_HOST_BIND="172.18.0.1")
        saved = self.root / "devpane/.build/host.env"
        saved.parent.mkdir(parents=True)
        saved.write_text("export DEVPANE_HOST_ADDR=172.17.0.1\n")
        self.run_action()
        self.assertIn("DEVPANE_HOST_ADDR=172.18.0.1", saved.read_text())

    def test_teardown_stops_host_proxy_when_compose_fails(self):
        self.env.update(TEST_OS="Linux", TEST_COMPOSE_EXIT="42")
        self.assertIn("host-proxy stop", self.run_action("down", expected=42))

    def test_invalid_action_does_not_install_or_start(self):
        self.assertEqual(self.run_action("invalid", expected=2), "")


if __name__ == "__main__":
    unittest.main()
