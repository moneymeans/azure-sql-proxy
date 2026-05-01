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

# 3. Start the proxy
node index.js \
  --server myserver.database.windows.net \
  --database mydb \
  --verbose

# 4. Connect your SQL client to:
#    Host:     127.0.0.1
#    Port:     1433
#    User:     anything (ignored)
#    Password: anything (ignored)
#    Database: mydb
```

You can also run it via the `bin` entry once installed globally or linked:

```bash
npm link
azure-sql-proxy --server myserver.database.windows.net --database mydb
```

## Usage

```
node index.js --server <azure-server> --database <database> [options]

Required:
  --server <host>         Azure SQL server (e.g. myserver.database.windows.net)
  --database <name>       Default database name

Options:
  --port <number>         Local port to listen on (default: 1433)
  --remote-port <number>  Azure SQL port (default: 1433)
  --verbose               Enable verbose logging
  --help                  Show this help
```

## How It Works

The proxy speaks the TDS (Tabular Data Stream) protocol on the client side and uses `tedious` on the Azure side. The flow is:

1. **PRELOGIN** — Client sends a TDS PRELOGIN; proxy responds advertising encryption-on.
2. **TLS handshake (client side)** — The proxy terminates TLS using a self-signed `localhost` certificate. TLS records are wrapped in TDS packets during the handshake (per the TDS spec) and switch to passthrough once secure.
3. **LOGIN7** — The client sends a LOGIN7 with whatever dummy credentials it likes. The proxy reads the requested database name out of the packet but otherwise discards the credentials.
4. **Azure connection** — The proxy opens a `tedious` connection to Azure SQL using your cached Entra ID access token, then sends a synthesised LOGINACK / ENVCHANGE response to the client so it considers the login successful.
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

1. Create a new **SQL Server** connection.
2. Set:
   - **Host**: `127.0.0.1`
   - **Port**: `1433` (or whatever you passed to `--port`)
   - **User**: anything (e.g. `proxy`)
   - **Password**: anything
   - **Database**: your database name
3. If TablePlus complains about the certificate, set SSL mode to **Preferred** (not Required), or disable SSL verification for this connection.

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
