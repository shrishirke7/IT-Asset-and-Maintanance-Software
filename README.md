# Northstar IT Inventory

Northstar is a self-hosted IT inventory and help-desk web app for Ubuntu Server. It uses PostgreSQL for shared records, Samba AD DS over LDAPS or StartTLS for sign-in and directory sync, and Caddy for HTTPS. The browser prototype still opens directly from `index.html`; production sign-in and shared data require the server below.

## Install on Ubuntu Server

For a public GitHub repository, the release can be installed with one command from a fresh Ubuntu Server 22.04+ host (replace `OWNER/REPO` with the published repository):

```bash
curl -fsSL https://raw.githubusercontent.com/OWNER/REPO/main/install-remote.sh | sudo bash -s -- OWNER/REPO main
```

The launcher fetches the selected branch and runs the same interactive installer as a local checkout. The installer asks whether the FQDN has public DNS and ports 80/443 forwarded to this server; answer yes to let Caddy obtain a public ACME certificate, or no to use its private CA for an internal-only network. Public access also requires routing/firewall rules, a DNS record, a publicly reachable FQDN, and the Samba AD server reachable from Ubuntu. Do not expose the application database or scanner ports directly to the Internet. Private GitHub repositories need an authenticated checkout method; never put a GitHub token in a shared install command.

1. Copy this project folder or its release archive to Ubuntu Server 22.04 or newer that can reach the Samba AD domain controller. Ensure the server has a static LAN IP.
2. Add a Samba DNS A record for the chosen app FQDN, pointing to the Ubuntu server. Make the name available to the employee workstations.
3. Create a read-only domain service account for directory lookups and an AD security group for inventory administrators. Put the desired administrators in that group. The account only needs to read users and their `displayName`, `mail`, `department`, `title`, `memberOf`, `userAccountControl`, and factory attribute.
4. Set the AD `department` attribute for each employee and set `physicalDeliveryOfficeName` to `ARG`, `ARB`, `ARC`, or `ARF`. If another AD attribute holds the factory code, enter its LDAP name in the installer.
5. From the copied project directory, run:

   ```bash
   sudo bash install.sh
   ```

6. Enter the app FQDN, Samba DNS/DC address, secure LDAP endpoint, base DN, UPN suffix, read-only service account and admin group DN. The account password is prompted without echo. For an internal AD certificate authority, provide its CA certificate PEM so the app can verify the DC certificate.
7. After installation, distribute `/opt/northstar-it/caddy-root.crt` to managed workstations and trust it as a root CA. On Windows, distribute it through Group Policy to **Local Computer → Trusted Root Certification Authorities**. This is required because the installer configures Caddy's private internal CA.
8. Open `https://<app-fqdn>` (append a non-default HTTPS port if chosen). Sign in with a Samba AD username and password. The user's name, department and factory come from AD.

## Additional AD / LDAP directories

After signing in as an inventory administrator, open **Settings → Active Directory / LDAP servers**. Add one configuration per directory: a name, host/IP, LDAPS or StartTLS port, read-only bind account, Base DN, and user/group LDAP filters. Test the secure connection before saving, then use **Sync** to import users and groups. The default filters target Active Directory; adjust them for OpenLDAP or a directory with a different schema. TLS certificate validation is always enabled.

Directory bind passwords are encrypted in PostgreSQL with a key derived from `APP_SECRET`; they are never returned to the browser. Keep the deployment `.env` (especially `APP_SECRET`) in a separate secure recovery copy, because losing that secret makes saved directory passwords unrecoverable. The app only reads directory objects. Add, disable, or remove accounts/groups in AD itself, then synchronize; **Remove cache** only deletes the local inventory copy and does not modify AD. Existing interactive sign-in and administrator authorization continue to use the primary directory configured during installation.

After the first install, update the project files and run `sudo bash update.sh`. It makes a manual backup first and preserves `.env`, database, uploads, and previous backups.

`LDAP_URL` must be `ldaps://dc.example.local:636`, or `ldap://dc.example.local:389` with StartTLS available. Plain, unencrypted LDAP is rejected. The Ubuntu server/container must resolve and reach the DC; the installer configures the Docker app's DNS resolver to the Samba DNS/DC IP. If LDAP uses an internal CA, that CA must be trusted by the app container via the installer prompt.

### AD values and permissions

- **Base DN:** the root naming context, for example `DC=office,DC=local`.
- **UPN suffix:** the suffix employees use to sign in, for example `office.local`.
- **Read-only account:** a regular service user, never Domain Admin. Store its password only in `/opt/northstar-it/.env`; the installer sets restrictive file permissions.
- **Admin group:** use the group's complete DN. Membership is checked against the user's direct `memberOf` values.
- **Factories:** map `physicalDeliveryOfficeName` to `ARG`, `ARB`, `ARC` or `ARF`, or configure another attribute in `.env`.

The app asks users to sign in with AD credentials over HTTPS. An IP address is not used as authentication. Silent Windows Integrated/Kerberos sign-in needs additional SPNEGO/reverse-proxy configuration for the exact client domain and browser policies.

## Backup and restore

The installer enables three Ubuntu systemd timers, using the server's local timezone:

- Daily at 01:30, keep 14 daily copies.
- Weekly Sunday at 02:30, keep 8 weekly copies.
- Monthly on day 1 at 03:30, keep 24 monthly copies.

Each archive contains a PostgreSQL custom-format dump, all ticket attachments and a SHA-256 manifest. Backup archives are private to the app/administrator on the server. Admins can also run a one-off backup from **Backup & restore** in the website. The data is in `/opt/northstar-it/backups`.

To restore, copy the desired archive to the server and run:

```bash
sudo /opt/northstar-it/restore.sh /opt/northstar-it/backups/northstar-daily-YYYYMMDDTHHMMSS.tar.gz
```

The restore script verifies the archive structure and checksums, creates a safety backup, requires typing `RESTORE`, pauses the web/app containers, restores the database and attachments, then starts them again. Download or copy backups to a separate encrypted NAS/backup system; a backup on the same server does not protect against loss of that server. `.env` is intentionally not included in the data backup because it contains the AD service password and application secrets. Keep a separate secured copy of the deployment configuration and credentials.

## Operations

```bash
cd /opt/northstar-it
sudo docker compose ps
sudo docker compose logs -f app
sudo systemctl list-timers 'northstar-backup*'
sudo /opt/northstar-it/backup.sh manual
```

Ports 80/443 are published by Caddy; PostgreSQL and Gunicorn are not directly exposed to the LAN. Gunicorn is bound to a loopback-only host port for the scanner companion. If another service already uses these ports, choose other ports in the installer. `compose.yaml` and the systemd timer/service files can be updated and reapplied after installation.

## Current scope

The deployable build includes secure Samba AD sign-in, directory import, group-based admin access, shared PostgreSQL tickets/inventory storage, ticket assignment/status/ETA/remarks, image uploads, scheduled/manual database-and-file backups, backup download and guarded command-line restore. On a fresh database, it also seeds a local `administrator1` account with the starter password `Admin@123` if that username is not already present; passwords are salted hashes in PostgreSQL, and the local administrator can change the password in Settings. Require HTTPS and change the starter password after the first sign-in. Network monitoring includes an Ubuntu host-network scanner companion. An administrator configures authorized private IPv4 CIDR ranges (each no larger than /24; 1,024 addresses total), starts an on-demand scan, watches progress, views IP/MAC/reverse-DNS/latency results, downloads a CSV report, and can add discovered equipment to inventory. Discovery uses ARP on directly attached subnets and sends one ICMP echo per address; it does not log into devices or inspect ports/files. MAC discovery is available for devices visible to the Ubuntu host at Layer 2; routed/VLAN-separated networks may require a scanner host at that site. The Windows Advanced IP Scanner executable is not embedded or executed; it is a signed compiled binary, not an application source-code package.
