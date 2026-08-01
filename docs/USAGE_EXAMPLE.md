Examples:

1. Persistent services

   Add enabled components to `zay.toml`, then:

   ```bash
   # background; logs: <data-dir>/logs/zay.log
   zay service start            # prompts for elevation only when configured stack needs TUN
   zay service status              # includes EasyTier peers and advertised mesh IPs
   zay service stop
   ```

   Inspect `<data-dir>/logs/zay.log`, `<data-dir>/logs/events.jsonl`, and
   `<data-dir>/logs/singbox.raw.log` directly.

   `[[http]]`, `[[fwd]]`, and `[[ssh]]` define persistent services. Their
   `zay run` counterparts remain one-off foreground tools.
   `zay run` does not read or create `zay.toml`; `zay run proxy` uses a
   per-invocation system temporary runtime directory.
   Add `--dump-config` to any `zay run` command to print equivalent
   persistent-service TOML, for example:

   ```bash
   zay run proxy -s "$SUB_URL" --dump-config > zay.toml
   ```

2. Network stack — recommended: srv (relay hub) + clients (node + subscription)

   Mesh CIDRs (e.g. `10.126.126.0/24`) are carried by EasyTier's own kernel TUN.
   sing-box TUN (when `-s` is set) excludes those CIDRs and only handles proxy traffic.
   Mesh **node** needs root for that TUN: use `sudo zay run …`, or `zay service start`
   (prompts once for sudo, then elevates the daemon with cached credentials).
   Nodes also listen on `tcp/udp :11010` by default so same-LAN peers can form a
   direct tunnel; otherwise bulk transfers stay on the public relay (~1 MB/s).
   Runtime files under the data dir are re-owned to `$SUDO_USER` so
   `zay service stop` / `status` / log reads still work without sudo.
   If stop fails after an older elevated run, use `sudo zay service stop`.

   # srv
   zay run proxy --mesh relay --mesh-auth "${NET}:${SECRET}" --mesh-ip 10.126.126.1/24

   # client A
   sudo zay run proxy --mesh node \
     --mesh-auth "${NET}:${SECRET}@tcp://${SRV_IP}:11010" \
     --mesh-ip 10.126.126.2/24 \
     -s "${SUB_URL}"

   # client B
   sudo zay run proxy --mesh node \
     --mesh-auth "${NET}:${SECRET}@tcp://${SRV_IP}:11010" \
     --mesh-ip 10.126.126.3/24 \
     -s "${SUB_URL}"

3. Static files / SPA development server
   zay run http --root dist --spa

4. Port relay
   zay run fwd --to tcp://0.0.0.0:8080 --from tcp://127.0.0.1:80

5. Database over WebSocket gateway
   On the database-side machine:
   zay run fwd --to http://0.0.0.0:18819/db --from tcp://db.internal:3306

   On the client machine:
   zay run fwd --to tcp://127.0.0.1:8899 --from http://public.example.com/db

   Connect through the local TCP port:
   mysql -h 127.0.0.1 -P 8899 -u USER -p

   Notes:
   - The gateway should route public.example.com/db to the database-side listener.
   - http:// endpoints are treated as WebSocket upgrade endpoints, not plain HTTP forwarding.
   - Gateway path redirects like /db -> /db/ are followed.

6. SSH local port forwarding
   zay run ssh -L 3307:10.0.0.5:3306 myserver

7. SSH through a jump host
   zay run ssh -J bastion -L 3307:mysql.internal:3306 app-server
