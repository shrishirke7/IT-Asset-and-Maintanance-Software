# Northstar IT Inventory

Northstar is a self-hosted IT inventory and help-desk app for Ubuntu Server. It uses PostgreSQL, local application accounts, Docker Compose, and Nginx.

## Install on Ubuntu Server

Copy or clone this complete project folder to Ubuntu Server 22.04 or newer, then run:

```bash
sudo bash install.sh
```

The installer installs Docker if needed, creates private deployment secrets and a self-signed HTTPS certificate, then starts the containers. It does not ask for company or directory details and does not create a default password. Open the URL printed at the end (default HTTPS port 8899) and finish the browser setup wizard. The first account becomes the application Administrator.

For a DNS name instead of the server IP, set `APP_FQDN` before running the installer, for example `sudo env APP_FQDN=inventory.example.com bash install.sh`. Default ports are 8898 (HTTP redirect) and 8899 (HTTPS), so the installation can coexist with services using 80/443. You can override `HTTP_PORT` and `HTTPS_PORT` the same way.

The initial certificate is self-signed, so browsers show a certificate warning until it is trusted or replaced with a certificate from your organization's CA. Access the app on the local network using the server IP or DNS name; remote access requires your own DNS, firewall/router forwarding, and TLS certificate setup.

## Accounts

The first-run browser wizard creates the first Administrator. After signing in, open **Settings → User accounts** to add regular User accounts and additional Administrators. Each account has its own username and password. Passwords and recovery answers are saved as salted hashes. Users can change their own password and set three recovery answers in Settings. Recovery answers are guessable personal facts, so choose private, hard-to-guess phrases; recovery attempts are rate-limited. Recovery questions are a convenience and are weaker than multi-factor authentication or a separately stored recovery code.

For a server-side administrator password reset when recovery answers have not been configured, run `sudo docker exec -it northstar-it-app-1 python reset_admin_password.py` on the Ubuntu server. The script prompts without echoing the password and changes only the named enabled Administrator account.

## Update

After copying the new project files onto the server, run:

```bash
cd /opt/northstar-it
sudo bash update.sh
```

The update script preserves `.env`, the PostgreSQL volume, uploads, and backups. Keep a protected copy of `.env`, especially `APP_SECRET` and `DB_PASSWORD`.

## Backups and restore

Manual backup:

```bash
sudo /opt/northstar-it/backup.sh manual
```

Restore a backup archive:

```bash
sudo /opt/northstar-it/restore.sh /opt/northstar-it/backups/<backup-file>
```

Daily, weekly, and monthly systemd timers are enabled by the installer. Keep another copy of important backups off the server.

## Scanner

Network discovery is an optional on-premise scanner. In **Network monitoring → Live network discovery**, an administrator saves authorized private IPv4 CIDR ranges (up to `/24` each and 1,024 total addresses), then starts a scan. The scanner must show **Scanner connected**; “Not configured” means no ranges have been saved. On Ubuntu, `ip -4 -o addr show scope global` shows the server's address and prefix; use your network administrator's approved subnet in CIDR form rather than guessing a range. Discovery uses ARP for directly attached subnets and one ICMP echo per address; it does not log into devices or inspect ports/files. Routed or VLAN-separated networks may need a scanner host at that site.

After ranges are saved, the scanner runs a background scan every 15 minutes. Assets and employees with an IP inside a saved range are marked Online when they reply to ICMP ping and Offline when they do not; records outside the authorized ranges remain Not checked. A device that blocks ICMP can appear Offline. Status timestamps are shown in the inventory and user list. Asset tags are generated as `SS-<category>-<six digits>` for new assets (DP, LP, PR, NS, NR, SV, MO, TB, AP, or FW).

## Service commands

```bash
cd /opt/northstar-it
sudo docker compose ps
sudo docker compose logs -f app web
sudo docker compose restart
```

App data and uploaded screenshots are stored in PostgreSQL and `/opt/northstar-it/uploads`. Nginx configuration is in `nginx/default.conf.template`.
