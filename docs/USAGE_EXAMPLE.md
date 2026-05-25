Examples:

1. Local proxy on this machine only
   zay stack --proxy "https://subscription.example"

2. Host/VM: Host acts as the forwarder for a Tart VM

   On the Host:
   1. Start a gateway proxy that VM clients can reach.
   2. Use --proxy if the Host should use a remote subscription.

   zay stack --gateway --mixed-port 7890
   zay stack --gateway --proxy "https://subscription.example" --mixed-port 7890

   On the VM:
   1. Put this in the VM data dir as mixin.yaml.
   2. Replace 192.168.64.1 if your Tart host gateway IP is different.

   mixin.yaml:
     mode: rule
     proxies:
       - name: Host
         type: socks5
         server: 192.168.64.1
         port: 7890
         udp: true
     rules:
       - DOMAIN-SUFFIX,example.com,Host
       - IP-CIDR,10.99.0.0/16,Host,no-resolve
       - IP-CIDR,192.168.0.0/16,DIRECT,no-resolve
       - IP-CIDR,172.16.0.0/12,DIRECT,no-resolve
       - IP-CIDR,100.64.0.0/10,DIRECT,no-resolve
       - IP-CIDR,127.0.0.0/8,DIRECT,no-resolve
       - IP-CIDR,169.254.0.0/16,DIRECT,no-resolve
       - IP-CIDR6,fc00::/7,DIRECT,no-resolve
       - MATCH,Host

   Start the VM stack with TUN enabled:
   sudo zay stack --tun --mixed-port 7890

   Notes:
   - ICMP/ping does not go through SOCKS; test TCP with curl.
   - Avoid broad DIRECT rules like IP-CIDR,10.0.0.0/8,DIRECT if internal services in 10.x should go through the Host.

3. Host joins private mesh and shares proxy with LAN/VM clients
   Configure [mesh] in zay.toml first.
   zay stack --mesh --gateway

4. Static files / SPA development server
   zay http --root dist --spa

5. Port relay
   zay fwd --to tcp://0.0.0.0:8080 --from tcp://127.0.0.1:80

6. SSH local port forwarding
   zay ssh -L 3307:10.0.0.5:3306 myserver

7. SSH through a jump host
   zay ssh -J bastion -L 3307:mysql.internal:3306 app-server
