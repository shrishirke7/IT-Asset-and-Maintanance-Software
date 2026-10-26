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

To move data to another server, create a manual backup on the current server and download its `.tar.gz` file from **Backup & restore → Backup files**. On the destination server, sign in as an administrator, open **Backup & restore**, upload the Northstar archive, and confirm by typing `RESTORE`. The app verifies the archive, creates a safety backup of the destination, then restores the database and uploaded attachments. The upload limit is 1 GB.

The restore replaces destination application records and attachments. It does not migrate `.env`, HTTPS certificates, or operating-system settings; keep the destination server's own configuration. For command-line recovery, the protected restore script remains available:

```bash
sudo /opt/northstar-it/restore.sh /opt/northstar-it/backups/<backup-file>
```

Daily, weekly, and monthly systemd timers are enabled by the installer. Keep another copy of important backups off the server.

## Scanner

Network discovery is an optional on-premise scanner. In **Network monitoring → Live network discovery**, an administrator saves authorized private IPv4 CIDR ranges (up to `/24` each and 1,024 total addresses), then starts a scan. The scanner must show **Scanner connected**; “Not configured” means no ranges have been saved. On Ubuntu, `ip -4 -o addr show scope global` shows the server's address and prefix; use your network administrator's approved subnet in CIDR form rather than guessing a range. Discovery uses ARP for directly attached subnets and one ICMP echo per address; it does not log into devices or inspect ports/files. Routed or VLAN-separated networks may need a scanner host at that site.

After ranges are saved, a subnet discovery scan runs every 15 minutes and known asset/employee IPs are pinged in the background about every 30 seconds. They are marked Online when they reply to ICMP ping and Offline when they do not; records outside the authorized ranges remain Not checked. A device that blocks ICMP can appear Offline. Status timestamps are shown in the inventory and user list. Asset tags are generated as `SS-<category>-<six digits>` for new assets (DP, LP, PR, NS, NR, SV, MO, TB, AP, FW, CCTV for CCTV, NVR for NVR, or DVR for DVR).


## Surveillance

Choose **Surveillance** as the asset type, then select **CCTV**, **NVR**, or **DVR** as its subtype in the shared asset form. The same asset form is available from the Surveillance page. The Surveillance page shows device lists, status, factory and department filters, and linked maintenance history. Add an IP address to a device for online/offline reachability checks through the existing network scanner; status is based on ICMP ping and does not inspect NVR camera channels or use vendor-specific camera APIs. Surveillance assets use the same asset records, backups, and service history as the rest of inventory. The sidebar Customize modules control lets each signed-in account reorder or hide workspace modules. Preferences are stored with the account on the server and follow the user across browsers.

### Live CCTV in Data Center

The Data Center page includes a **Live CCTV · Hubs & rooms** panel. Register a camera first as an Asset inventory item with type **Surveillance** and subtype **CCTV**. An administrator can select **Add live camera**, choose the asset, hub/area, room, and camera profile. Built-in RTSP presets cover UNV, Hikvision, Dahua, and Axis; other RTSP-compatible brands can use **Other brand · custom RTSP path** with the manufacturer’s documented endpoint. HTTP/HTTPS is supported only when the camera exposes a direct MJPEG/HLS media endpoint; its web login page on port 80/443 is not itself a video stream. go2rtc bridges supported sources to browser WebRTC. Signed-in users can open a configured **Live view**; only administrators can add or remove feeds.

Live video requires a network route from the media server to the selected camera stream protocol and port (commonly RTSP TCP 554), and between authorized viewer devices and the app server (WebRTC TCP/UDP 8555). Cameras can remain in a separate VLAN if routing/firewall rules permit these connections. In `/opt/northstar-it/.env`, set `WEBRTC_BIND_IP` to the app server's private interface IP and `WEBRTC_CANDIDATE` to the private IP clients can reach. Keep `WEBRTC_PORT=8555`. Allow TCP and UDP 8555 only from authorized viewer subnets in the host firewall; do not expose this media port to the public Internet. Keep the go2rtc API on the internal Docker network. Apply firewall and environment changes according to the site's network policy, then run `sudo docker compose up -d --build`.

Camera passwords are encrypted in the app database. go2rtc maintains its protected runtime stream configuration inside a Docker named volume; do not publish that volume or add it to Git/backup exports. If an admin removes a feed, its go2rtc stream is removed. Use the in-app **Help center** for the setup steps and troubleshooting checklist. Device ping status and video playback are separate checks.
## Notifications

Administrators can create alert rules in **Notifications** for one asset category or selected devices, choose Online/Offline status transitions, select recipient accounts, and choose email and/or WhatsApp. Alerts are queued when a known asset changes status; the scanner checks known device IPs about every 30 seconds. Initial `Not checked` status does not trigger an alert. Recipients need an email address or phone number in their account profile. WhatsApp recipients must have opted in.

Email delivery is optional. Add `SMTP_HOST`, `SMTP_PORT`, `SMTP_USERNAME`, `SMTP_PASSWORD`, `SMTP_FROM`, and `SMTP_STARTTLS` to the private `/opt/northstar-it/.env` file. WhatsApp delivery uses Meta's WhatsApp Business Cloud API. Configure `WHATSAPP_ACCESS_TOKEN`, `WHATSAPP_PHONE_NUMBER_ID`, `WHATSAPP_API_VERSION`, `WHATSAPP_TEMPLATE_NAME`, and `WHATSAPP_TEMPLATE_LANGUAGE` in that same private file. The approved message template must have four body parameters in this order: device name, asset tag, current status, and IP address. After adding provider settings, run `sudo docker compose up -d --force-recreate scanner` from `/opt/northstar-it`. Never commit provider secrets to Git.

## Service commands

```bash
cd /opt/northstar-it
sudo docker compose ps
sudo docker compose logs -f app web
sudo docker compose restart
```

App data and uploaded screenshots are stored in PostgreSQL and `/opt/northstar-it/uploads`. Nginx configuration is in `nginx/default.conf.template`.
