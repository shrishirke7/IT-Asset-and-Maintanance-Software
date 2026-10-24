# Parts catalog and stock update

Included files:
- `index.html` — separate product catalog, stock receipt and assignment flows, photo and custom category fields, and Excel-compatible workbook export.
- `server.py` — persists catalog products and stock receipt history in the existing app-state database.

## Deploy on Ubuntu with Docker Compose

Copy these updated files into the existing project directory, preserving `.env`, `uploads/`, `backups/`, and the database volume. Then run from that directory:

```bash
docker compose up -d --build app
```

If the project uses a different Compose service name, rebuild the existing application service with its configured name. Do not run `docker compose down -v` or remove the PostgreSQL volume; this update is intended to keep the current data. After the container is healthy, reload the site with Ctrl+F5.

Existing combined part/stock rows are linked into the new product catalog automatically when loaded. The current balance and assignment references remain in place.