# azure-sql-proxy

Local TDS proxy that lets you connect to Azure SQL databases using Entra ID (Azure AD) authentication with MFA support -- from any SQL client, including TablePlus.

## The Problem

Many SQL clients (TablePlus, DBeaver, etc.) don't support Azure AD/Entra ID MFA authentication for Azure SQL databases. This means if your organisation enforces MFA, you're stuck using SSMS or Azure Data Studio.

## The Solution

This proxy sits between your SQL client and Azure SQL:

```
TablePlus (SQL Auth)  -->  azure-sql-proxy (localhost:1433)  -->  Azure SQL (Entra ID + MFA)
```

It intercepts the TDS connection, replaces your dummy credentials with a real Azure AD token (obtained from your `az login` session), and transparently bridges all traffic. Your SQL client thinks it's talking to a regular SQL Server.

## Prerequisites

1. **Node.js** 18+ (for TLS API support)
2. **Azure CLI** ([install](https://docs.microsoft.com/en-us/cli/azure/install-azure-cli))
3. **OpenSSL** (for generating a local TLS certificate -- pre-installed on macOS/Linux)

## Quick Start

```bash
# 1. Install dependencies
npm install

# 2. Login to Azure (handles MFA in your browser -- only needed once per session)
az login

# 3. Start the proxy
node index.js --server myserver.database.windows.net --database mydb --verbose

# 4. Connect TablePlus to:
#    Host: 127.0.0.1
#    Port: 1433
#    User: anything
#    Pass: anything
#    Database: mydb
```

## Usage

```
node index.js --server <azure-server> --database <database> [options]

Required:
  --server <host>        Azure SQL server (e.g. myserver.database.windows.net)
  --database <name>      Default database name

Options:
  --port <number>        Local port to listen on (default: 1433)
  --remote-port <number> Azure SQL port (default: 1433)
  --verbose              Enable verbose logging
  --help                 Show this help
```

## How it Works

The proxy implements the TDS (Tabular Data Stream) protocol handshake:

1. **PRELOGIN** -- Client sends a prelogin request. The proxy forwards it to Azure SQL and relays the response back.
2. **TLS Handshake** -- The proxy terminates TLS on both sides: it acts as a TLS server for your client (using a self-signed localhost certificate) and as a TLS client to Azure SQL.
3. **LOGIN7 Rewrite** -- Your client sends a Login7 packet with dummy SQL credentials. The proxy discards it and builds a new Login7 with FEDAUTH (Federated Authentication) using your Azure AD token.
4. **Bridge** -- After authentication succeeds, the proxy pipes all TDS traffic bidirectionally. Every query, result set, RPC call, bulk load, and transaction flows through transparently.

### Token Management

- Tokens are obtained via `az account get-access-token --resource https://database.windows.net/`
- Tokens are cached in memory and refreshed 5 minutes before expiry (~1 hour lifetime)
- If your `az login` session expires, restart the proxy after re-running `az login`

### TLS Certificate

On first run, the proxy generates a self-signed certificate stored at `~/.azure-sql-proxy/`. Your SQL client may warn about the self-signed cert -- this is expected and safe since the connection is to localhost.

In TablePlus, you may need to uncheck "Use SSL" or set SSL mode to "Preferred" rather than "Required", depending on how it handles self-signed certs.

## TablePlus Configuration

1. Create a new SQL Server connection
2. Set:
   - **Host**: `127.0.0.1`
   - **Port**: `1433` (or whatever you set with `--port`)
   - **User**: `proxy` (or anything -- it's ignored)
   - **Password**: `proxy` (or anything -- it's ignored)
   - **Database**: your database name
3. Test the connection

## Troubleshooting

### "Failed to get Azure token"

Run `az login` and try again. Your session may have expired.

### "Port 1433 is already in use"

Use a different port: `node index.js --server ... --database ... --port 11433`

Then configure TablePlus to connect to port `11433`.

### Connection timeout

- Ensure your Azure SQL server's firewall allows connections from your IP
- Check that the server name is correct (should end with `.database.windows.net`)
- Run with `--verbose` to see detailed connection logs

### TLS errors

If you see TLS-related errors, ensure:

- Your Node.js version is 18+
- OpenSSL is installed (`openssl version`)
- The cert files in `~/.azure-sql-proxy/` aren't corrupted (delete them to regenerate)

## License

MIT
# azure-sql-proxy
