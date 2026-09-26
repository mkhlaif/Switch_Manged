# Network setup

## 1. Web access from other PCs (LAN)

By default the web ports are published on **127.0.0.1 only** (`BIND_ADDRESS=127.0.0.1`), so a
fresh install is reachable only from the server itself. To let other PCs on the internal network
use it:

1. **Use HTTPS.** Put the certificate in `certs/tls.crt` and the key in `certs/tls.key` (internal
   CA recommended) and set `NGINX_SITE=https.conf`. With `COOKIE_SECURE=true` (default) browsers
   only send the session cookie over HTTPS — plain `http://SERVER-IP:8080` logins fail by design.
   nginx runs as the unprivileged user **uid 101**, so on Linux the key must be readable by it:

   ```bash
   sudo chown 101:101 certs/tls.key certs/tls.crt && sudo chmod 400 certs/tls.key
   ```

   Otherwise the web container restarts with `cannot load certificate key … Permission denied`
   (`docker compose logs frontend`). On Windows with Docker Desktop no change is needed.
   Tested on Ubuntu 24.04: HTTPS health, HSTS, CSP and the HTTP → HTTPS redirect (which keeps a
   non-standard `HTTPS_PORT`).
2. **Choose the interface:** `BIND_ADDRESS=<server LAN/management IP>` (preferred) or `0.0.0.0`
   (all interfaces).
3. **Ports:** `HTTPS_PORT` (default 8443) and `HTTP_PORT` (default 8080, redirects to HTTPS in
   `https.conf` mode). To use the standard ports set `HTTPS_PORT=443` and `HTTP_PORT=80`.
4. Apply: `docker compose up -d`.
5. **Host firewall:** allow the HTTPS port from the management network only
   ([WINDOWS_SETUP.md](WINDOWS_SETUP.md#7-firewall-only-for-access-from-other-pcs),
   [LINUX_SETUP.md](LINUX_SETUP.md#7-firewall)).
6. Users open `https://SERVER-IP:8443` (or `https://server-name:8443` with DNS).

```
PC (10.x.x.x) ──HTTPS 8443──► server BIND_ADDRESS:8443 ──(Docker port mapping)──► nginx :8443
```

**Never publish the application to the Internet** (no port forwarding on the Internet router, no
public load balancer). It is an internal network-operations tool.

### Behind a TLS load balancer / reverse proxy

Use `NGINX_SITE=http.conf`, point the load balancer to `SERVER:8080`, and make sure it sets
`X-Forwarded-Proto: https`. nginx overwrites `X-Forwarded-For` with the peer address, so without
further configuration the audit log shows the load balancer's IP. To record real client IPs, add
to the `server` block in `frontend/nginx/http.conf`:

```nginx
set_real_ip_from 10.0.0.5;          # the load balancer's address
real_ip_header   X-Forwarded-For;
```

Only trust addresses you control: a client-supplied `X-Forwarded-For` must never be trusted
directly (this was audit finding S1).

### Client IP in the audit log with Docker Desktop

On Docker Desktop (Windows/macOS) connections are NATed, so the audit log records the Docker
gateway address (for example `172.20.0.1`) instead of the PC's IP. On Linux with Docker Engine,
connections from other machines keep their real source address (connections from the server
itself to `127.0.0.1` show the Docker gateway).

### Limits in the web proxy

nginx refuses request bodies over 1 MB (12 MB for the switch import upload) and limits each
client IP to 30 logins per minute and about 20 API requests per second (bursts allowed); excess
requests get HTTP 413 / 429. The backend enforces the same body limits and its own per-user
limits. Many users behind one NAT address share the per-IP budget — raise the `rate=` values in
`frontend/nginx/http.conf` / `https.conf` if that is your situation.

### Docker networks

The containers use two networks: `edge` (nginx and backend; the backend's outbound SSH to the
switches and HTTPS to NetBox/Zabbix leave through it) and `data` (backend and PostgreSQL, internal
— no route outside). Nothing but the web ports is published on the host.

## 2. Connectivity to the switches

| From | To | Protocol | Purpose |
|---|---|---|---|
| server running Docker | switch management IPs | **TCP/22 (SSH)** | all read and restart operations |
| server | NetBox URL (optional) | HTTPS | read-only API |
| server | Zabbix URL (optional) | HTTPS | read-only JSON-RPC API |

Requirements:

- The server (the `backend` container uses the host's routing via Docker NAT) must reach the
  switches' **management addresses**; allow TCP/22 in any firewall/ACL between them.
- SSH must be enabled on the switches and the account below must be allowed to log in from the
  server's address (switch ACLs / `aaa` configuration).
- **Account:** create a dedicated local or RADIUS/TACACS account for the application. Read-only
  privileges are enough while the platform is read-only; for port restarts it additionally needs
  the privilege to run the interface admin-state (AOS 8) / interface admin (AOS 6) commands and,
  for PoE cycling, `lanpower`. Never use a shared personal account.
- **Host keys:** every switch's SSH host key must be enrolled in the application (compare the
  fingerprint with the switch console). The application refuses to connect otherwise.
- Old AOS 6 switches may need *Legacy SSH algorithms* enabled per switch in the inventory.

Do not put production credentials into documentation, tickets or the repository; they are
entered only in the application (*Settings → Credentials*), where they are stored encrypted.
