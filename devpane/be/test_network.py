"""Real data-path tests. Run with `mise devpane:test` after `mise devpane`."""
import fcntl
import json
import os
from pathlib import Path
import subprocess
import time
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
COMPOSE = ["docker", "compose", "-f", str(ROOT / "compose.yaml"), "--project-directory", str(ROOT)]
HOST = os.environ["DEVPANE_HOST_ADDR"]
RESULTS = []
# Serialize outage tests against this lab.
lock = (ROOT / ".build/network-test.lock").open("w")
try:
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
except BlockingIOError:
    raise SystemExit("Another devpane network test is running.")


def run(*args, check=True):
    result = subprocess.run(args, capture_output=True, text=True, timeout=45)
    if check and result.returncode:
        raise AssertionError(f"{' '.join(args)}: {result.stderr.strip()} {result.stdout.strip()}")
    return result


def inside(service, *args, check=True):
    return run(*COMPOSE, "exec", "-T", service, *args, check=check)


def api(path, method="GET"):
    request = urllib.request.Request("http://127.0.0.1:18787/api/v1/" + path,
                                     data=b"{}" if method == "POST" else None,
                                     headers={"Content-Type": "application/json"}, method=method)
    with urllib.request.urlopen(request, timeout=40) as response:
        return json.load(response)


def curl(url, service="zay", proxy=False, resolve=False, check=True):
    args = ["curl", "--ipv4", "-fsS", "--connect-timeout", "2", "--max-time", "5"]
    args += ["--noproxy", "" if proxy else "*"]
    if proxy:
        args += ["--proxy", f"http://{HOST}:13128"]
    if resolve:
        args += ["--resolve", "devpane.test:80:192.0.2.11"]
    return inside(service, *args, url, check=check)


def retry(check, timeout=40):
    deadline = time.monotonic() + timeout
    while True:
        try:
            return check()
        except (AssertionError, OSError, ValueError) as error:
            if time.monotonic() >= deadline:
                raise error
            time.sleep(1)


def record(name, check):
    start = time.monotonic()
    try:
        detail = check()
    except Exception as error:
        RESULTS.append({"name": name, "passed": False, "error": str(error)})
        print(f"FAIL {name}: {error}", flush=True)
        raise
    RESULTS.append({"name": name, "passed": True, "seconds": round(time.monotonic() - start, 2), "detail": detail})
    print(f"PASS {name}", flush=True)
    return detail


def equal(actual, expected):
    assert actual == expected, (actual, expected)
    return actual


host_pid = int((ROOT / ".build/host-proxy.pid").read_text())


def proxy_request(resolve=False, explicit=False):
    body = json.loads(curl("http://devpane.test/whoami", proxy=explicit, resolve=resolve).stdout)
    equal(body["via"], "proxy")
    equal(body["role"], "host")
    equal(body["pid"], host_pid)
    return body


def mesh_request():
    body = json.loads(curl("http://10.126.126.3:8090/whoami").stdout)
    equal(body["via"], "direct")
    equal(body["client"], "10.126.126.2")
    return body


def ready():
    state = api("state")
    equal(state["core"]["stack"]["proxy_ready"], True)
    assert any(m["connected_peers"] >= 1 for m in state["mesh"]), state["mesh"]
    return state["core"]["stack"]


stopped_core = stopped_host = stopped_peer = False
try:
    record("core reports proxy and Mesh ready", lambda: retry(ready))
    def native_process():
        command = run("ps", "-p", str(host_pid), "-o", "command=").stdout.strip()
        assert str(ROOT / ".build/host-target/release/devpane-be") in command, command
        return command
    record("proxy is a native host process", native_process)
    def subscription():
        body = curl(f"http://{HOST}:18090/sub").stdout
        assert f"server: {HOST}" in body and "port: 13128" in body, body
        return body
    record("subscription loads from outside Docker", subscription)
    record("explicit proxy reaches the host fixture", lambda: proxy_request(explicit=True))
    record("lab DNS returns reserved test address", lambda: equal(inside("zay", "dig", "+short", "+time=2", "+tries=1", "@172.30.126.10", "devpane.test", "A").stdout.strip(), "192.0.2.11"))
    def tun_route():
        route = json.loads(inside("zay", "ip", "-j", "route", "get", "192.0.2.11").stdout)[0]
        assert route["dev"].startswith("tun"), route
        return route
    record("reserved destination routes through TUN", tun_route)
    record("transparent HTTP crosses TUN to host proxy", lambda: proxy_request(resolve=True))
    def stale_fakeip():
        # An uncached address used to terminate the entire TUN read task.
        inside("zay", "sh", "-c", "printf stale | nc -u -w 1 198.19.255.254 12345", check=False)
        return proxy_request(resolve=True)
    record("TUN survives a stale FakeIP packet", stale_fakeip)
    record("DNS and transparent HTTP work together", proxy_request)
    record("excluded control-plane HTTP stays direct", lambda: equal(json.loads(curl("http://172.30.126.10:8090/whoami").stdout)["via"], "direct"))
    record("Mesh HTTP crosses virtual IPs", lambda: retry(mesh_request))
    def mesh_route():
        route = json.loads(inside("zay", "ip", "-j", "route", "get", "10.126.126.3").stdout)[0]
        assert route["dev"].startswith("tun"), route
        equal(route["prefsrc"], "10.126.126.2")
        assert route["dev"] != tun_route()["dev"], route
        return route
    record("Mesh uses its own TUN interface", mesh_route)
    record("Mesh ICMP and 1200-byte payload", lambda: inside("zay", "ping", "-c", "3", "-W", "2", "-s", "1200", "10.126.126.3").stdout)
    record("reverse Mesh ICMP", lambda: inside("mesh-peer", "ping", "-c", "3", "-W", "2", "10.126.126.2").stdout)

    stopped_host = True
    run("bash", str(ROOT / "be/host-proxy.sh"), "stop")
    record("host proxy outage breaks transparent HTTP", lambda: equal(curl("http://devpane.test/whoami", resolve=True, check=False).returncode != 0, True))
    record("Mesh survives host proxy outage", mesh_request)
    run("bash", str(ROOT / "be/host-proxy.sh"), "start")
    host_pid = int((ROOT / ".build/host-proxy.pid").read_text())
    stopped_host = False
    record("TUN recovers when host proxy returns", lambda: retry(lambda: proxy_request(resolve=True)))

    stopped_peer = True
    run(*COMPOSE, "stop", "mesh-echo", "mesh-peer")
    record("Mesh peer outage breaks virtual-IP HTTP", lambda: equal(curl("http://10.126.126.3:8090/whoami", check=False).returncode != 0, True))
    record("TUN survives Mesh peer outage", lambda: proxy_request(resolve=True))
    run(*COMPOSE, "start", "mesh-peer", "mesh-echo")
    stopped_peer = False
    record("Mesh recovers after peer restart", lambda: retry(mesh_request))

    stopped_core = True
    api("core/stop", "POST")
    record("stopping core removes transparent proxy path", lambda: equal(curl("http://devpane.test/whoami", resolve=True, check=False).returncode != 0, True))
    record("host proxy remains available without TUN", lambda: proxy_request(explicit=True))
    api("core/start", "POST")
    stopped_core = False
    record("TUN recovers after core restart", lambda: retry(lambda: proxy_request(resolve=True)))
    record("Mesh recovers after core restart", lambda: retry(mesh_request))
finally:
    restorations = []
    if stopped_host:
        restorations.append(lambda: run("bash", str(ROOT / "be/host-proxy.sh"), "start"))
    if stopped_peer:
        restorations.append(lambda: run(*COMPOSE, "start", "mesh-peer", "mesh-echo"))
    if stopped_core:
        restorations.append(lambda: api("core/start", "POST"))
    for restore in restorations:
        try:
            restore()
        except Exception as error:
            RESULTS.append({"name": "restore lab service", "passed": False, "error": str(error)})
            print(f"Restoration failed: {error}", flush=True)
    report = ROOT / ".build/network-test.json"
    report.write_text(json.dumps(RESULTS, indent=2) + "\n")
    print(f"Report: {report}", flush=True)
print(f"All {len(RESULTS)} network checks passed.", flush=True)
