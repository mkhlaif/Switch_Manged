# Linux setup (Ubuntu 22.04 / 24.04)

Commands for a fresh Ubuntu server. Other modern distributions work the same way once Git,
Docker Engine and the Compose plugin are installed.

## 1. Install Git, OpenSSL and Docker

```bash
sudo apt update
sudo apt install -y git openssl ca-certificates curl

# Docker Engine + Compose plugin from Docker's official repository
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] \
https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "$VERSION_CODENAME") stable" \
  | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt update
sudo apt install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

# allow your user to run docker (log out and back in afterwards)
sudo usermod -aG docker "$USER"
```

Check (after logging in again):

```bash
docker version && docker compose version
```

## 2. Get the project

```bash
sudo mkdir -p /opt/netops && sudo chown "$USER": /opt/netops
git clone https://github.com/mkhlaif/Switch_Manged.git /opt/netops/Switch_Manged
cd /opt/netops/Switch_Manged
```

## 3. Create `.env`

```bash
./scripts/init-env.sh
chmod 600 .env
nano .env
```

Keep `READ_ONLY_MODE=true` and `NETWORK_COMMAND_EXECUTION=DISABLED`. Store
`CREDENTIAL_ENCRYPTION_KEY` in your password manager.

### HTTPS (recommended for any access from other PCs)

Certificate from your internal CA → `certs/tls.crt` and `certs/tls.key`, or a self-signed one for
testing:

```bash
openssl req -x509 -newkey rsa:2048 -nodes -keyout certs/tls.key -out certs/tls.crt \
  -days 825 -subj "/CN=$(hostname -f)"
chmod 600 certs/tls.key
```

In `.env`: `NGINX_SITE=https.conf`, and for LAN access `BIND_ADDRESS=<server LAN IP>` (see
[NETWORK_SETUP.md](NETWORK_SETUP.md)).

## 4. Start

```bash
docker compose up -d --build
docker compose ps          # all services "healthy"
```

Migrations run automatically at backend start. The services restart automatically after a reboot
(`restart: unless-stopped`) as long as Docker is enabled: `sudo systemctl enable docker`.

## 5. First administrator

```bash
docker compose exec backend python -m app.cli create-user --role admin admin
```

## 6. Open and check

```bash
curl -fsS http://127.0.0.1:8080/health          # http.conf
curl -fsSk https://127.0.0.1:8443/health        # https.conf (self-signed)
```

Browser: `https://SERVER-IP:8443` (after the network setup) or `http://localhost:8080` on the
server. Continue with [DEPLOYMENT.md](DEPLOYMENT.md#4-first-time-configuration).

## 7. Firewall

**Important:** ports published by Docker are **not** filtered by `ufw` rules (Docker inserts its
own iptables rules). Restrict access with `BIND_ADDRESS` (listen only on the management interface)
and, if you need source filtering, with rules in the `DOCKER-USER` chain:

```bash
# allow HTTPS only from the management network 10.10.0.0/16
sudo iptables -I DOCKER-USER -p tcp --dport 8443 ! -s 10.10.0.0/16 -j DROP
# make it persistent, e.g.: sudo apt install -y iptables-persistent && sudo netfilter-persistent save
```

SSH to the switches (TCP/22 outbound) must be allowed from the server to the switch management
addresses.

## 8. Logs, updates, backups

```bash
docker compose logs -f backend                    # live logs
docker compose logs --since 1h backend | grep SECURITY
./scripts/backup.sh                               # backup into ./backups
```

- Updates: [UPGRADE.md](UPGRADE.md) (always back up first).
- Backups and restore: [BACKUP_RESTORE.md](BACKUP_RESTORE.md). Example nightly cron job:

```bash
( crontab -l 2>/dev/null; echo "30 2 * * * cd /opt/netops/Switch_Manged && ./scripts/backup.sh /var/backups/netops >> /var/log/netops-backup.log 2>&1" ) | crontab -
```

## 9. Troubleshooting (Linux)

| Problem | Fix |
|---|---|
| `permission denied while trying to connect to the Docker daemon socket` | log out/in after `usermod -aG docker`, or use `sudo docker …` |
| `port is already allocated` | change `HTTP_PORT` / `HTTPS_PORT` in `.env` |
| other PCs cannot connect | `BIND_ADDRESS` still `127.0.0.1`, or blocked in `DOCKER-USER` / network firewall |
| backend `unhealthy` | `docker compose logs backend` — usually a wrong `CREDENTIAL_ENCRYPTION_KEY` or database password change after the first start |

More: [TROUBLESHOOTING.md](TROUBLESHOOTING.md).
