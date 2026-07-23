Examples:

1. Network stack — recommended: srv (relay hub) + clients (node + subscription)

   # srv
   zay stack --mesh relay --mesh-auth "${NET}:${SECRET}" --mesh-ip 10.126.126.1/24

   # client A
   sudo zay stack --mesh node \
     --mesh-auth "${NET}:${SECRET}@tcp://${SRV_IP}:11010" \
     --mesh-ip 10.126.126.2/24 \
     -s "${SUB_URL}"

   # client B
   sudo zay stack --mesh node \
     --mesh-auth "${NET}:${SECRET}@tcp://${SRV_IP}:11010" \
     --mesh-ip 10.126.126.3/24 \
     -s "${SUB_URL}"

2. Static files / SPA development server
   zay http --root dist --spa

3. Port relay
   zay fwd --to tcp://0.0.0.0:8080 --from tcp://127.0.0.1:80

4. Database over WebSocket gateway
   On the database-side machine:
   zay fwd --to http://0.0.0.0:18819/db --from tcp://db.internal:3306

   On the client machine:
   zay fwd --to tcp://127.0.0.1:8899 --from http://public.example.com/db

   Connect through the local TCP port:
   mysql -h 127.0.0.1 -P 8899 -u USER -p

   Notes:
   - The gateway should route public.example.com/db to the database-side listener.
   - http:// endpoints are treated as WebSocket upgrade endpoints, not plain HTTP forwarding.
   - Gateway path redirects like /db -> /db/ are followed.

5. SSH local port forwarding
   zay ssh -L 3307:10.0.0.5:3306 myserver

6. SSH through a jump host
   zay ssh -J bastion -L 3307:mysql.internal:3306 app-server

7. Web control plane
   zay serve
