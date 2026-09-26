# Windows setup

Tested on Windows 11 with Docker Desktop 4.x (Docker Engine 28.5, Compose 2.40, WSL 2 back end),
Git for Windows 2.53 and Windows PowerShell 5.1 — the commands below were run as written on a
clean copy of the repository (init, build, admin creation, import, backup, restore). Run the
commands in **PowerShell**.

## 1. Install the software

| Software | Where | Notes |
|---|---|---|
| Git for Windows | https://git-scm.com/download/win | default options; includes OpenSSL for certificates |
| Docker Desktop | https://www.docker.com/products/docker-desktop/ | choose the **WSL 2** back end; reboot when asked |

Check:

```powershell
git --version
docker version
docker compose version
```

`docker version` must show a **Server** section (Docker Desktop is running).

## 2. Get the project

```powershell
cd $HOME
git clone https://github.com/mkhlaif/Switch_Manged.git
cd Switch_Manged
```

## 3. Create `.env`

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\init-env.ps1
notepad .env
```

The script generates `POSTGRES_PASSWORD` and `CREDENTIAL_ENCRYPTION_KEY` and never overwrites an
existing `.env`. Keep the safe defaults (`READ_ONLY_MODE=true`,
`NETWORK_COMMAND_EXECUTION=DISABLED`). **Copy `CREDENTIAL_ENCRYPTION_KEY` to a password manager.**

Only local access (this PC): nothing else to change. Access from other PCs: see
[NETWORK_SETUP.md](NETWORK_SETUP.md) (set `BIND_ADDRESS`, use HTTPS, open the firewall).

### Optional: HTTPS with a self-signed certificate

```powershell
& "C:\Program Files\Git\usr\bin\openssl.exe" req -x509 -newkey rsa:2048 -nodes `
  -keyout certs\tls.key -out certs\tls.crt -days 825 -subj "/CN=$env:COMPUTERNAME"
```

Then in `.env`: `NGINX_SITE=https.conf`. Use a certificate from your internal CA for production.

## 4. Start

```powershell
docker compose up -d --build
docker compose ps
```

The first build takes several minutes. All three services must become `healthy`. Database
migrations run automatically when the backend starts.

## 5. Create the first administrator

```powershell
docker compose exec backend python -m app.cli create-user --role admin admin
```

Type the password when asked (12+ characters, three of: lower case, upper case, digit, symbol);
it is not shown while typing. For a scripted installation the password can be piped instead:

```powershell
"<password>" | docker compose exec -T backend python -m app.cli create-user --role admin --password-stdin admin
```

(Windows PowerShell adds a CR/LF to piped text; the tool strips it — older versions did not.)

## 6. Open the application

- `http://localhost:8080` (or `https://localhost:8443` with `NGINX_SITE=https.conf`)
- Health: `http://localhost:8080/health` → `"status":"healthy"`

After signing in, the safety indicator shows **STOPPED** / **READ ONLY**: nothing can change a
switch. Continue with the first-time configuration in [DEPLOYMENT.md](DEPLOYMENT.md#4-first-time-configuration).

## 7. Firewall (only for access from other PCs)

```powershell
# Run PowerShell as Administrator. Allow HTTPS from the internal network only.
New-NetFirewallRule -DisplayName "Network Operations HTTPS" -Direction Inbound -Protocol TCP `
  -LocalPort 8443 -Action Allow -Profile Domain,Private -RemoteAddress 10.0.0.0/8
```

Adjust `-RemoteAddress` to your management network. Do not allow the port on the *Public*
profile.

## 8. Everyday commands

```powershell
docker compose ps                  # status
docker compose logs -f backend     # logs (Ctrl+C to stop following)
docker compose restart backend     # restart the backend
docker compose down                # stop (data is kept)
.\scripts\backup.ps1               # database backup into .\backups
```

## 9. Troubleshooting (Windows)

| Problem | Fix |
|---|---|
| `docker: error during connect` / no Server section | start Docker Desktop and wait until it says *running* |
| `WSL 2 installation is incomplete` | run `wsl --update` as Administrator, reboot |
| `Bind for 127.0.0.1:8080 failed: port is already allocated` | another program uses the port; set `HTTP_PORT=8081` in `.env` and `docker compose up -d` |
| `running scripts is disabled on this system` | use `powershell -ExecutionPolicy Bypass -File …` as shown |
| Login works on this PC but not from another PC | set `BIND_ADDRESS`, use HTTPS (`COOKIE_SECURE=true` needs HTTPS except on `localhost`), open the firewall — see [NETWORK_SETUP.md](NETWORK_SETUP.md) |
| Line-ending problems after cloning | the repository enforces LF via `.gitattributes`; re-clone if files were edited with CRLF conversion |

More: [TROUBLESHOOTING.md](TROUBLESHOOTING.md).
