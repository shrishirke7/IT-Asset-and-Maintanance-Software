# Billing filters and Vendors / Suppliers update

This update changes `index.html` and `server.py` only. It adds:

- Billing filters for invoice number, from/to date, factory, department, and Paid/Unpaid status.
- A Vendors / Suppliers tab with vendor search, add/edit/remove, and fields for vendor name, company, address, telephone, mobile, email, city, state, and pincode.
- Vendor selection on invoice forms; saved invoices retain vendor name and vendor ID.
- Vendor records stored in app state and writable by administrators. Existing invoices keep their vendor text if a vendor is later removed.

## Apply on Ubuntu

Transfer `index.html` and `server.py` from this archive to `/opt/northstar-it`. Back up the current files first:

```sh
cd /opt/northstar-it
sudo cp index.html "index.html.bak.$(date +%Y%m%d-%H%M%S)"
sudo cp server.py "server.py.bak.$(date +%Y%m%d-%H%M%S)"
```

Then rebuild the app container:

```sh
cd /opt/northstar-it
sudo docker compose up -d --build app
sudo docker compose logs --tail=60 app
```

Open the app and hard refresh with `Ctrl+Shift+R`. The archive does not contain `.env`, database data, uploads, or backups. This package has not been deployed to the Ubuntu host.
