"""Native macOS guest checks; compilation always happens on the host."""
import fcntl
import json
import ipaddress
import os
from pathlib import Path
import shlex
import subprocess
import time
import sys
import signal

SERVE = "--serve" in sys.argv
def shutdown(signum, frame):
    raise SystemExit(0)
signal.signal(signal.SIGTERM, shutdown)

ROOT = Path(__file__).resolve().parents[2]
STATE = ROOT / "devpane/.build/macos"
STATE.mkdir(parents=True, exist_ok=True)
LOCK = (ROOT / "devpane/.build/network-test.lock").open("w")
fcntl.flock(LOCK, fcntl.LOCK_EX | fcntl.LOCK_NB)
if SERVE:
    (STATE / "devpane.pid").write_text(str(os.getpid()))
IP = (STATE / "ip").read_text().strip()
OPTIONS = ["-o", "BatchMode=yes", "-o", "ConnectTimeout=10", "-o",
           f"UserKnownHostsFile={STATE}/known_hosts", "-i", str(STATE / "id_ed25519")]
SSH = ["ssh", *OPTIONS, f"admin@{IP}"]
COMPOSE = ["docker", "compose", "-f", str(ROOT / "devpane/compose.yaml"),
           "--project-directory", str(ROOT / "devpane")]
RESULTS = []
GATEWAY = None


def run(args, *, check=True, timeout=90):
    result = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    if check and result.returncode:
        raise AssertionError(f"{shlex.join(args)}: {result.stdout}\n{result.stderr}")
    return result


def guest(command, **kwargs):
    return run([*SSH, command], **kwargs)


def copy(path, destination):
    return run(["scp", *OPTIONS, str(path), f"admin@{IP}:{destination}"], timeout=600)


def record(name, check):
    start = time.monotonic()
    try:
        detail = check()
        RESULTS.append({"name": name, "passed": True, "detail": detail,
                        "seconds": round(time.monotonic() - start, 2)})
        print(f"PASS {name}", flush=True)
        return detail
    except Exception as error:
        RESULTS.append({"name": name, "passed": False, "error": str(error)})
        print(f"FAIL {name}: {error}", flush=True)
        raise


def require(condition, detail):
    assert condition, detail
    return detail


def retry(check, seconds=60):
    deadline = time.monotonic() + seconds
    while True:
        try:
            return check()
        except (AssertionError, subprocess.TimeoutExpired):
            if time.monotonic() >= deadline:
                raise
            time.sleep(2)


def api(action):
    return guest("curl -fsS --max-time 30 -X POST -H 'Content-Type: application/json' "
                 f"-d '{{}}' http://127.0.0.1:8787/api/v1/core/{action}").stdout


def curl(url, *, mesh=False, check=True, resolve=False, status=False):
    args = ["curl", "-4", "-fsSL", "--connect-timeout", "5", "--max-time", "40",
            "--noproxy", "" if mesh else "*"]
    if mesh:
        args += ["--proxy", "http://10.126.126.3:7890"]
    if resolve:
        args += ["--resolve", "devpane.test:80:192.0.2.11"]
    if status:
        args += ["--write-out", "\n%{http_code}"]
    return guest(shlex.join([*args, url]), check=check)


def browser_capture(args, output, *, dom=False):
    # Chrome on macOS can keep running after producing its requested output.
    # Wait for the artifact explicitly and always terminate our own browser.
    stdout = output if dom else output + ".stdout"
    complete = (f"grep -qi '</html>' {shlex.quote(output)}" if dom
                else f"test -s {shlex.quote(output)}")
    script = (
        f"rm -f {shlex.quote(output)}; "
        f"{shlex.join(args)} > {shlex.quote(stdout)} 2> {shlex.quote(output + '.stderr')} & "
        "pid=$!; trap 'kill \"$pid\" 2>/dev/null || true' EXIT; "
        "for attempt in {1..45}; do "
        f"if {complete}; then exit 0; fi; "
        "if ! kill -0 \"$pid\" 2>/dev/null; then break; fi; sleep 1; done; "
        f"cat {shlex.quote(output + '.stderr')} >&2; exit 1"
    )
    guest("/bin/bash -c " + shlex.quote(script), timeout=60)
    return guest("cat " + shlex.quote(output)).stdout if dom else None


def fixture():
    body = json.loads(curl("http://devpane.test/whoami", resolve=True).stdout)
    return require(body["via"] == "proxy", body)


def mesh_fixture():
    body = json.loads(curl("http://10.126.126.3:8090/whoami").stdout)
    return require(body["client"] == "10.126.126.4", body)


def stop_guest_processes():
    guest("cd ~/zay-lab; for name in zay dns; do "
          "test -f $name.pid || continue; pid=$(cat $name.pid); "
          "case $(ps -p \"$pid\" -o command=) in "
          "'./zay webui '*|'./devpane-be') sudo -n kill \"$pid\";; esac; "
          "sudo -n rm -f $name.pid; done", check=False)


def host_fixture():
    env = dict(os.environ, DEVPANE_ROLE="host", DEVPANE_BIND=GATEWAY,
               DEVPANE_IPV4_ONLY="1", DEVPANE_ADVERTISE_HOST=GATEWAY,
               DEVPANE_CONTROL_PORT="18091", DEVPANE_PROXY_PORT="13129")
    return subprocess.Popen([str(ROOT / "devpane/.build/host-target/release/devpane-be")],
                            env=env, stdout=HOST_LOG, stderr=subprocess.STDOUT,
                            start_new_session=True)


HOST_LOG = (STATE / "host-proxy.log").open("a")
proxy = None
tunnel = None
dns_service = None
original_dns = None
peer_stopped = False
try:
    version = guest("sw_vers; uname -s; uname -m").stdout
    record("guest is native macOS ARM64", lambda: require("Darwin" in version and "arm64" in version, version))
    stop_guest_processes()
    default_route = guest("route -n get default").stdout
    GATEWAY = next(line.split(":", 1)[1].strip() for line in default_route.splitlines() if "gateway:" in line)
    # Publish only the relay's TCP control/data transport on host loopback.
    override = STATE / "relay.yaml"
    override.write_text('services:\n  relay:\n    ports:\n      - "127.0.0.1:11110:11010"\n')
    run([*COMPOSE, "-f", str(override), "up", "-d", "--no-deps", "relay"])
    proxy = host_fixture()
    tunnel = subprocess.Popen(["ssh", *OPTIONS, "-N", "-o", "ExitOnForwardFailure=yes",
                               "-o", "ServerAliveInterval=15",
                               "-R", "127.0.0.1:11110:127.0.0.1:11110",
                               *(["-L", "127.0.0.1:18788:127.0.0.1:8787"] if SERVE else []), f"admin@{IP}"],
                              start_new_session=True)
    retry(lambda: guest(f"curl -fsS --max-time 3 http://{GATEWAY}:18091/sub"))
    copy(ROOT / "devpane/.build/host-target/release/devpane-be", "zay-lab/devpane-be")
    guest("chmod +x ~/zay-lab/devpane-be; cd ~/zay-lab; "
          "sudo -n sh -c 'DEVPANE_ROLE=dns DEVPANE_CONTROL_PORT=18092 DEVPANE_DOH=1 "
          "DEVPANE_IPV4_ONLY=1 nohup ./devpane-be > dns.log 2>&1 < /dev/null & echo $! > dns.pid'")
    config = (ROOT / "devpane/zay.toml").read_text()
    config = config.replace("@DEVPANE_HOST@:18090", f"{GATEWAY}:18091")
    config = config.replace("172.30.126.10:8090", f"{GATEWAY}:18091")
    config = config.replace("172.30.126.10", IP)
    config = config.replace("172.30.126.30/32", "223.5.5.5/32")
    config = config.replace("172.30.126.30:11010", "127.0.0.1:11110")
    config = config.replace("10.126.126.2/24", "10.126.126.4/24")
    config = config.replace('name = "devpane"\nnetwork_name', 'name = "devpane-macos"\nnetwork_name')
    (STATE / "zay.toml").write_text(config)
    copy(STATE / "zay.toml", "zay-lab/zay.toml")
    guest("sudo -n touch /etc/zay-devpane-macos; cd ~/zay-lab; sudo -n sh -c '"
          f"ZAY_LAB=devpane-macos ZAY_LAB_WORKDIR=/Users/admin/zay-lab ZAY_LAB_DIRECT_URL=http://{GATEWAY}:18091/whoami "
          "nohup ./zay webui --listen 127.0.0.1:8787 "
          "--data-dir ./data --config ./zay.toml > zay.log 2>&1 < /dev/null & echo $! > zay.pid'")
    retry(fixture)
    services = guest("networksetup -listallnetworkservices").stdout.splitlines()[1:]
    dns_service = next(service for service in services if service and not service.startswith("*"))
    original_dns = guest(f"networksetup -getdnsservers {shlex.quote(dns_service)}").stdout.strip()
    generated = json.loads(guest("sudo -n cat ~/zay-lab/data/singbox/config.json").stdout)
    tun = next(inbound for inbound in generated["inbounds"] if inbound["type"] == "tun")
    tun_ipv4 = next(ipaddress.ip_interface(address) for address in tun["address"] if ":" not in address)
    tun_dns = str(tun_ipv4.ip + 1)
    guest(f"sudo -n networksetup -setdnsservers {shlex.quote(dns_service)} {tun_dns}")
    guest("sudo -n dscacheutil -flushcache; sudo -n killall -HUP mDNSResponder")
    # Copy the browser application only, never the host browser profile.
    chrome = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
    if guest(f"test -x {shlex.quote(chrome)}", check=False).returncode:
        archive = STATE / "Chrome.zip"
        run(["ditto", "-c", "-k", "--keepParent", "/Applications/Google Chrome.app", str(archive)], timeout=600)
        copy(archive, "zay-lab/Chrome.zip")
        guest("sudo -n ditto -x -k ~/zay-lab/Chrome.zip /Applications", timeout=600)
    if SERVE:
        retry(mesh_fixture)
        print("macOS devpane ready: http://127.0.0.1:18788/ (Darwin guest)", flush=True)
        while True:
            if tunnel.poll() is not None or proxy.poll() is not None:
                raise RuntimeError("macOS lab tunnel or host proxy stopped")
            time.sleep(2)
    record("transparent HTTP traverses macOS TUN", fixture)
    record("system DNS and transparent TUN work together", lambda: require(
        json.loads(curl("http://devpane.test/whoami").stdout)["via"] == "proxy", "host proxy reached"))
    def google_dns():
        output = guest("dscacheutil -q host -a name google.com").stdout
        addresses = [line.split(":", 1)[1].strip() for line in output.splitlines()
                     if line.startswith("ip_address:")]
        return require(addresses and all(ipaddress.ip_address(address) in ipaddress.ip_network("198.18.0.0/15")
                                         for address in addresses), output)
    record("macOS system resolver retains Google FakeIP mapping", google_dns)
    guest("printf stale | nc -u -w 1 198.19.255.254 12345", check=False, timeout=10)
    record("macOS TUN survives a stale FakeIP packet", fixture)
    record("Mesh virtual HTTP carries macOS peer source address", lambda: retry(mesh_fixture))
    tun_route = guest("route -n get 192.0.2.11").stdout
    mesh_route = guest("route -n get 10.126.126.3").stdout
    def interface(text):
        return next(line.split(":", 1)[1].strip() for line in text.splitlines() if "interface:" in line)
    record("TUN and Mesh use separate macOS utun devices", lambda: require(
        interface(tun_route).startswith("utun") and interface(mesh_route).startswith("utun")
        and interface(tun_route) != interface(mesh_route), {"tun": tun_route, "mesh": mesh_route}))
    record("Mesh ICMP with 1200-byte payload", lambda: guest("ping -c 3 -W 2000 -s 1200 10.126.126.3").stdout)
    record("reverse Mesh ICMP reaches macOS", lambda: run([*COMPOSE, "exec", "-T", "mesh-peer",
        "ping", "-c", "3", "-W", "2", "10.126.126.4"]).stdout)
    def concurrent_tun():
        for _ in range(3):
            # Start the requests inside the guest; 24 new SSH handshakes would
            # exercise sshd's MaxStartups limit instead of TUN concurrency.
            output = guest("jot 24 | xargs -P 24 -I X curl -4 -fsS --noproxy '*' "
                           "--resolve devpane.test:80:192.0.2.11 --connect-timeout 5 --max-time 15 "
                           "-o /dev/null -w '%{http_code}\\n' http://devpane.test/whoami").stdout
            statuses = output.splitlines()
            require(len(statuses) == 24 and all(status == "200" for status in statuses), output)
        return {"rounds": 3, "connections_per_round": 24}
    record("72 concurrent TUN requests in three rounds", concurrent_tun)
    for mesh in (False, True):
        for domain, marker in (("baidu.com", "百度"), ("google.com", "Google")):
            label = "mesh" if mesh else "tun"
            def external(mesh=mesh, domain=domain, marker=marker, label=label):
                # -f verifies the HTTP response and curl verifies the TLS certificate.
                body, status = curl(f"https://{domain}", mesh=mesh, status=True).stdout.rsplit("\n", 1)
                require(status == "200", f"{domain} HTTP {status}")
                require(marker in body, f"Unexpected {domain} response: {body[:200]}")
                path = f"/Users/admin/zay-lab/{label}-{domain}.png"
                args = [chrome, "--headless", "--disable-gpu", "--disable-quic",
                        "--disable-background-networking", "--no-first-run",
                        f"--user-data-dir=/tmp/zay-chrome-{label}-{domain}-{time.time_ns()}",
                        "--window-size=1280,800", "--virtual-time-budget=5000",
                        f"--screenshot={path}",
                        "--proxy-server=http://10.126.126.3:7890" if mesh else "--no-proxy-server",
                        f"https://{domain}"]
                browser_capture(args, path)
                dom_args = [arg for arg in args if not arg.startswith("--screenshot=")]
                dom_args = [arg + "-dom"
                            if arg.startswith("--user-data-dir=") else arg for arg in dom_args]
                dom_args.insert(-1, "--dump-dom")
                dom = browser_capture(dom_args, path + ".html", dom=True)
                require(marker in dom and "chrome-error://chromewebdata" not in dom,
                        f"Browser did not render expected {domain} content")
                local = STATE / f"{label}-{domain}.png"
                run(["scp", *OPTIONS, f"admin@{IP}:{path}", str(local)])
                require(local.read_bytes().startswith(b"\x89PNG\r\n\x1a\n") and local.stat().st_size > 10000,
                        f"Invalid rendering: {local}")
                return {"url": f"https://{domain}", "status": int(status), "screenshot": str(local), "html_marker": marker}
            try:
                record(f"macOS {label}: {domain} HTTPS and browser rendering", external)
            except Exception:
                pass  # Still exercise and report all four independent paths.
    proxy.terminate()
    proxy.wait(timeout=10)
    record("host proxy outage breaks macOS TUN proxy path", lambda: require(
        curl("http://devpane.test/whoami", resolve=True, check=False).returncode != 0, "TUN request must fail"))
    record("Mesh virtual traffic survives host proxy outage", mesh_fixture)
    proxy = host_fixture()
    record("macOS TUN recovers after host proxy restart", lambda: retry(fixture))
    run([*COMPOSE, "stop", "mesh-echo", "mesh-peer"])
    peer_stopped = True
    record("Mesh peer outage breaks virtual data path", lambda: require(
        curl("http://10.126.126.3:8090/whoami", check=False).returncode != 0, "Mesh request must fail"))
    record("Mesh peer outage breaks Internet gateway", lambda: require(
        curl("https://google.com", mesh=True, check=False).returncode != 0, "Mesh Internet request must fail"))
    record("macOS TUN survives Mesh peer outage", fixture)
    run([*COMPOSE, "start", "mesh-peer", "mesh-echo"])
    peer_stopped = False
    record("macOS Mesh recovers after peer restart", lambda: retry(mesh_fixture))
    record("Mesh Internet recovers after peer restart", lambda: retry(lambda: require(
        "Google" in curl("https://google.com", mesh=True).stdout, "Google HTTPS restored")))
    api("stop")
    record("stopped core removes transparent proxy path", lambda: require(
        curl("http://devpane.test/whoami", resolve=True, check=False).returncode != 0, "TUN request must fail"))
    api("start")
    record("macOS TUN recovers after core restart", lambda: retry(fixture))
    record("macOS Mesh recovers after core restart", lambda: retry(mesh_fixture))
finally:
    if peer_stopped:
        run([*COMPOSE, "start", "mesh-peer", "mesh-echo"], check=False)
    guest("curl -sS --max-time 30 -X POST -H 'Content-Type: application/json' -d '{}' "
          "http://127.0.0.1:8787/api/v1/core/stop", check=False)
    if dns_service and original_dns is not None:
        addresses = original_dns.splitlines() if "There aren't any DNS Servers" not in original_dns else ["Empty"]
        guest(shlex.join(["sudo", "-n", "networksetup", "-setdnsservers", dns_service, *addresses]), check=False)
    stop_guest_processes()
    if tunnel:
        tunnel.terminate()
        tunnel.wait(timeout=10)
    if proxy and proxy.poll() is None:
        proxy.terminate()
        proxy.wait(timeout=10)
    if not SERVE:
        (STATE / "network-test.json").write_text(json.dumps({"platform": "macOS", "results": RESULTS}, indent=2) + "\n")
    HOST_LOG.close()

raise SystemExit(0 if RESULTS and all(result["passed"] for result in RESULTS) else 1)
