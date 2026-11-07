# Software issues update

This bundle updates the app UI in `index.html`. It does not change the database schema.

Included: SSD capacity units (GB/TB), persistent font saving fix, per-asset deep links and detail history, optional network management URL, employee register CSV export, parts stock value, and scrollable/sticky tables. The Asset Inventory factory filter, OS type/version, multiple employee IP fields, factory display-name editing, and current asset value were already present in the workspace.

## Deploy on the Ubuntu app server

From Windows, in the project folder:

```powershell
scp .\index.html cloudserver1@192.168.130.17:/tmp/northstar-index.html
```

Then SSH to the server and run:

```sh
cd /opt/northstar-it
sudo cp index.html "index.html.bak.$(date +%Y%m%d-%H%M%S)"
sudo cp /tmp/northstar-index.html ./index.html
sudo docker compose build app
sudo docker compose up -d app
```

After it is up, sign in and hard-refresh the browser (Ctrl+Shift+R). The management URL field is optional and should contain only the device web UI address, without credentials. Asset links use the `?asset=TAG` query parameter and open after sign-in.
