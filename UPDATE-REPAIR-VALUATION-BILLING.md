# Repair workflow, Valuation and Billing update

This update contains the changed application source files only. It does not include your database, `.env`, camera credentials, uploads, or backups.

## What this adds

- Three-stage repair cases under **Maintenance & repairs**: device intake, diagnosis/work with multiple parts, then completion and hand-back.
- Repair parts are checked against the selected factory's New, Repaired or Refurbished stock. Saving the work stage deducts stock and records the part issue against the repair, asset, factory, department and assigned user. Re-saving an edited work stage restores the old issue before applying the corrected lines.
- Repair cases cannot skip a stage. Saved stages can be reopened for correction.
- Department cards show asset counts, current recorded value, and online/offline totals.
- Overview dashboard metric tiles open the related inventory view.
- **Valuation** shows current asset value by category and a filtered weekly/monthly/quarterly/yearly ledger for maintenance and invoice costs, with factory, department and user filters and Excel-readable export.
- **Billing / Invoices** includes paid/unpaid totals, searchable invoice list/detail, line items with GST calculation, edits, exports and up to five attachments per invoice (10 MB each).
- Invoice data is stored in the server app state and files in the existing uploads volume. Changes are restricted to administrators; signed-in users can read invoices and download their files.

## Deploy to the Ubuntu host

The update is not applied to the remote host by copying files into this workspace. Transfer `server.py` and `index.html` from this archive to the Ubuntu server, then run the following there:

```sh
cd /opt/northstar-it
sudo cp server.py "server.py.bak.$(date +%Y%m%d-%H%M%S)"
sudo cp index.html "index.html.bak.$(date +%Y%m%d-%H%M%S)"
```

Copy the two archive files over the existing `/opt/northstar-it/server.py` and `/opt/northstar-it/index.html` (for example, extract the archive on your PC and use your normal SFTP client). Then rebuild the app container:

```sh
cd /opt/northstar-it
sudo docker compose up -d --build app
sudo docker compose logs --tail=60 app
```

Open the app and hard-refresh the browser (`Ctrl+Shift+R`). Do not replace `.env`, the database, `uploads`, or backups. If rollback is needed, restore the two timestamped backup files and rebuild the app container again.

## Notes

- Expense reports use costs already saved in maintenance/repair records and invoices; historical expenses that were never entered cannot be inferred automatically.
- Asset valuation uses the current value recorded on each asset.
- Invoice attachments are limited to five files total per invoice and 10 MB per file. Allowed extensions: PDF, common image formats, Office documents, ODT and TXT.
- The Excel export is SpreadsheetML `.xls`, which Excel can open directly.
