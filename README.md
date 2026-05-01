# azure-sql-proxy

A local TDS proxy that lets you connect to Azure SQL with Entra ID (Azure AD) MFA authentication from any SQL client — including TablePlus, DBeaver, and others that don't support Azure AD interactive auth.

## The Problem

Most third-party SQL clients don't implement Azure AD / Entra ID interactive (MFA) authentication for Azure SQL. If your organisation enforces MFA, you're typically stuck with SSMS or Azure Data Studio.

## The Solution

This proxy sits between your SQL client and Azure SQL:

```
TablePlus (SQL Auth)  -->  azure-sql-proxy (127.0.0.1:1433)  -->  Azure SQL (Entra ID + MFA)
```

The proxy:

1. Acts as a TDS server on `127.0.0.1` so any SQL client can connect with dummy credentials.
2. Acquires an Azure AD access token from your local `az login` session.
3. Opens an authenticated connection to Azure SQL (via [`tedious`](https://www.npmjs.com/package/tedious) using `azure-active-directory-access-token` auth).
4. Translates each incoming SQL batch / transaction request into a `tedious` request and streams the results back as TDS tokens.

Your SQL client thinks it's talking to a normal SQL Server; Azure SQL sees an authenticated Entra ID session.

## Prerequisites

- **Node.js** 18+
- **Azure CLI** — [install instructions](https://docs.microsoft.com/en-us/cli/azure/install-azure-cli)
- **OpenSSL** — used once to generate a local TLS cert (pre-installed on macOS/Linux)

## Quick Start

```bash
# 1. Install dependencies
npm install

# 2. Login to Azure (interactive MFA in your browser)
az login

# 3. Start the proxy. --server is the Azure SQL host to forward to;
#    --database is optional because TablePlus sends it in its LOGIN7
#    packet (the proxy will use whatever the client requests).
node index.js \
  --server myserver.database.windows.net \
  --verbose

# 4. In TablePlus create a SQL Server connection with:
#    Host:     127.0.0.1
#    Port:     1433
#    User:     anything (ignored)
#    Password: anything (ignored)
#    Database: mydb           <-- the proxy uses this per-connection
```

The proxy reads the **database** field from each client's LOGIN7 packet, so one proxy instance can serve multiple TablePlus connections pointing at different databases on the same Azure SQL server without restarting. To switch Azure servers, restart with a different `--server` (or run a second proxy on a different `--port`).

You can also run the binary directly:

```bash
npm link
azure-sql-proxy --server myserver.database.windows.net --verbose
```

## Usage

```
node index.js --server <host> [options]

Options:
  --server <host>         Default Azure SQL server (e.g. myserver.database.windows.net).
                          The proxy will use this unless the client's LOGIN7
                          packet specifies a different *.database.windows.net
                          host (most clients send the proxy's address there, so
                          in practice this is the host the proxy connects to).
  --database <name>       Default database name. Optional — most clients
                          (TablePlus, DBeaver, etc.) send the database in their
                          LOGIN7 packet and the proxy uses that, so you usually
                          don't need this.
  --port <number>         Local port to listen on (default: 1433).
  --remote-port <number>  Azure SQL port (default: 1433).
  --verbose               Enable verbose logging.
  --help                  Show this help.
```

## How It Works

The proxy speaks the TDS (Tabular Data Stream) protocol on the client side and uses `tedious` on the Azure side. The flow is:

1. **PRELOGIN** — Client sends a TDS PRELOGIN; proxy responds advertising encryption-on.
2. **TLS handshake (client side)** — The proxy terminates TLS using a self-signed `localhost` certificate. TLS records are wrapped in TDS packets during the handshake (per the TDS spec) and switch to passthrough once secure.
3. **LOGIN7** — The client sends a LOGIN7 with whatever dummy credentials it likes. The proxy reads the **ServerName** and **Database** fields out of the packet, discarding the rest. The Database field is used as-is. The ServerName field is used *only if it's a valid Azure SQL host* (`*.database.windows.net`); otherwise the proxy falls back to the `--server` flag (most clients send the proxy's own address here, e.g. `127.0.0.1`, which is correctly ignored).
4. **Azure connection** — The proxy opens a `tedious` connection to the resolved Azure SQL server using your cached Entra ID access token, then sends a synthesised LOGINACK / ENVCHANGE response to the client so it considers the login successful.
5. **Bridge mode** — Subsequent TDS messages from the client are decoded and dispatched:
   - `SQL_BATCH` (`0x01`) — executed via `tedious.execSqlBatch`; column metadata, rows, and a DONE token are streamed back.
   - `TRANSACTION_MANAGER` (`0x0e`) — `BEGIN` / `COMMIT` / `ROLLBACK` / `SAVE TRANSACTION` are translated to SQL batches.
   - `ATTENTION` (`0x06`) — cancels the in-flight `tedious` request.
   - `RPC` (`0x03`) — currently returns a "not supported" error (see [Limitations](#limitations)).

### Token management

- Tokens are obtained via `az account get-access-token --resource https://database.windows.net/`.
- Tokens are cached in memory and refreshed 5 minutes before expiry.
- If your `az login` session expires, re-run `az login` and restart the proxy.

### TLS certificate

On first run a self-signed certificate is generated and stored at `~/.azure-sql-proxy/{key,cert}.pem`. Your SQL client may warn about the self-signed cert — this is expected because it's only used for the local hop to `127.0.0.1`. The connection from the proxy to Azure SQL is encrypted independently with proper certificate validation by `tedious`.

## TablePlus Configuration

The simplest setup, and the one TablePlus is designed for:

1. Start the proxy with a default server: `node index.js --server myserver.database.windows.net --verbose`.
2. In TablePlus create a **SQL Server** connection:
   - **Host**: `127.0.0.1`
   - **Port**: `1433` (or whatever you passed to `--port`).
   - **User**: anything (e.g. `proxy`).
   - **Password**: anything.
   - **Database**: the database you want to use (TablePlus will send this in LOGIN7 and the proxy will use it).
3. If TablePlus complains about the certificate, set SSL mode to **Preferred** (not Required), or disable SSL verification for this connection.

To switch to a different Azure server, restart the proxy with a different `--server`, or run multiple proxy instances on different ports (`--port 1434` etc.) and point each TablePlus connection at the matching port.

### Routing multiple servers through one proxy

The proxy reads the server name from each client's LOGIN7 packet, so in principle one proxy instance can route to multiple Azure servers. The catch is that TablePlus (and any TCP client) does its own DNS lookup of the Host field and connects to that IP — so to route by LOGIN7 you'd need to either add `/etc/hosts` entries pointing each Azure hostname to `127.0.0.1`, or use a client that lets you set the server name independently of the TCP target.

## Security Notes

- The proxy listens on `127.0.0.1` only, so it isn't reachable from the network.
- **There is no authentication on the local listener.** While the proxy is running, *any local process* under your user account can connect to it and run queries against Azure SQL using your Entra ID token. Don't leave the proxy running on a shared / multi-user machine, and shut it down (`Ctrl+C`) when you're not actively using it.
- The Azure-side connection is TLS with proper certificate validation by `tedious`. The local-hop TLS uses a self-signed cert stored at `~/.azure-sql-proxy/`, with the private key written `0600`.

## Limitations

This is a pragmatic proxy, not a full TDS server. Known gaps:

- **No RPC support** — Prepared statements and parameterised queries sent as `RPCRequest` (TDS type `0x03`) return a "not supported" error. Most clients work fine with plain SQL batches, but some ORMs / drivers default to RPC. Workaround: configure your client to send literal SQL where possible.
- **Result types are coerced to NVARCHAR** — All column values are returned as strings (`NVARCHAR`). Numeric / date / binary types display correctly but their original type information is lost. This keeps the row encoder simple and works for browsing data; it's not suitable for binary-faithful tooling.
- **No bulk load / TVP / MARS** — Only single-statement batches and basic transactions.
- **One concurrent request per connection** — Messages are queued and dispatched sequentially because `tedious` runs one request at a time.

If any of these matter for your workflow, the relevant code is all in `index.js` (`handleClientMessage` / `buildColMetadataToken` / `buildRowToken`).

## Troubleshooting

**"Failed to get Azure token"** — Run `az login` and retry. Your session likely expired.

**"Port 1433 is already in use"** — Pass `--port 11433` (or any free port) and update your client accordingly.

**Connection timeout to Azure** —
- Verify your Azure SQL firewall allows your client IP.
- Confirm the server hostname ends with `.database.windows.net`.
- Re-run with `--verbose` to see where the handshake stalls.

**TLS errors on the local hop** —
- Ensure Node.js is 18+.
- Try deleting `~/.azure-sql-proxy/` to regenerate the certificate.
- Confirm `openssl version` works.

## Project Status & Contributing

This is provided **as-is**. It scratches my own itch and I don't plan to keep it actively maintained or respond to issues — but if it's useful to you:

- **Fork it** and adapt it to your needs.
- **Pull requests are welcome** — I'll review them when I get the chance, no promises on timing.
- **No support, no warranty, no liability.** See the licence below.

## License

MIT License — see standard MIT terms. The software is provided "AS IS", without warranty of any kind, express or implied, including but not limited to the warranties of merchantability, fitness for a particular purpose, and non-infringement. In no event shall the author be liable for any claim, damages, or other liability arising from the use of this software.
