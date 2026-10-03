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
        for name in ("manage.sh", "macos-runtime.sh"):
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
        self.mock("uname", 'echo "$TEST_OS"')
        self.mock("mise", '''
printf 'mise %s\\n' "$*" >> "$TEST_LOG"
if [[ "$4" == devpane:macos ]]; then exec /bin/bash "$2/devpane/be/macos-runtime.sh" "$6"; fi
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

    def test_macos_installs_tools_and_starts_isolated_vm(self):
        self.env.update(DOCKER_HOST="tcp://elsewhere:2376", DOCKER_CONTEXT="other",
                        DOCKER_TLS_VERIFY="1", DOCKER_CONFIG="/do/not/change")
        calls = self.run_action()
        self.assertIn("run devpane:macos -- up", calls)
        self.assertIn("colima --profile zay-devpane start --runtime docker --vm-type vz --activate=false", calls)
        self.assertIn(f"host=unix://{self.env['COLIMA_HOME']}/zay-devpane/docker.sock|context=|tls=", calls)
        self.assertIn("run devpane:host-build", calls)
        self.assertIn("up -d mesh-peer mesh-echo zay", calls)
        self.assertLess(calls.index("host-proxy start"), calls.index("up -d mesh-peer mesh-echo zay"))
        self.assertIn("host-proxy start", calls)
        self.assertIn("network=default", calls)
        for plugin in ("compose", "buildx"):
            link = self.root / "devpane/.build/docker/cli-plugins" / f"docker-{plugin}"
            self.assertEqual(link.resolve(), self.bin / f"docker-cli-plugin-docker-{plugin}")

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
                self.assertIn(f"run devpane:macos -- {action}", calls)

    def test_linux_uses_existing_engine(self):
        self.env.update(TEST_OS="Linux", DOCKER_HOST="unix:///existing.sock")
        calls = self.run_action()
        self.assertIn("run devpane:host-build", calls)
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
