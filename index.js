#!/usr/bin/env node

"use strict";

const net = require("net");
const tls = require("tls");
const { execSync } = require("child_process");
const fs = require("fs");
const path = require("path");
const os = require("os");
const crypto = require("crypto");
const { Duplex } = require("stream");
const { Connection } = require("tedious");
const { versions: TDS_VERSIONS } = require("tedious/lib/tds-versions");

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

const args = parseArgs(process.argv.slice(2));

if (args.help) {
  printUsage();
  process.exit(0);
}

const CONFIG = {
  localPort: parseInt(args.port || "1433", 10),
  azureServer: args.server || "",
  azurePort: parseInt(args["remote-port"] || "1433", 10),
  database: args.database || "",
  verbose: !!args.verbose,
};

if (!CONFIG.azureServer || !CONFIG.database) {
  console.error("Error: --server and --database are required.\n");
  printUsage();
  process.exit(1);
}

// ---------------------------------------------------------------------------
// TDS Constants
// ---------------------------------------------------------------------------

const TDS_HEADER_LEN = 8;
const PKT = {
  SQL_BATCH: 0x01,
  TABULAR_RESULT: 0x04,
  LOGIN7: 0x10,
  PRELOGIN: 0x12,
};
const STATUS_EOM = 0x01;

// ---------------------------------------------------------------------------
// Azure Token Cache
// ---------------------------------------------------------------------------

let cachedToken = null;
let tokenExpiresAt = 0;

function getAzureToken() {
  const now = Date.now();
  if (cachedToken && tokenExpiresAt - now > 5 * 60 * 1000) {
    return cachedToken;
  }

  log("Acquiring Azure AD token via az cli...");
  try {
    const raw = execSync(
      "az account get-access-token --resource https://database.windows.net/ --output json",
      { encoding: "utf8", timeout: 30000 },
    );
    const parsed = JSON.parse(raw);
    cachedToken = parsed.accessToken;
    tokenExpiresAt = parsed.expires_on * 1000;
    log("Token acquired, expires", new Date(tokenExpiresAt).toISOString());
    return cachedToken;
  } catch (err) {
    console.error("Failed to get Azure token. Run `az login` first.");
    throw err;
  }
}

// ---------------------------------------------------------------------------
// TDS Helpers
// ---------------------------------------------------------------------------

function wrapTds(type, payload) {
  const hdr = Buffer.alloc(TDS_HEADER_LEN);
  hdr.writeUInt8(type, 0);
  hdr.writeUInt8(STATUS_EOM, 1);
  hdr.writeUInt16BE(TDS_HEADER_LEN + payload.length, 2);
  hdr.writeUInt16BE(0, 4);
  hdr.writeUInt8(1, 6);
  hdr.writeUInt8(0, 7);
  return Buffer.concat([hdr, payload]);
}

class TdsMessageReader {
  constructor() {
    this.buffer = Buffer.alloc(0);
  }

  append(data) {
    this.buffer = Buffer.concat([this.buffer, data]);
  }

  tryReadMessage() {
    let payloads = [];
    let msgType = null;
    let consumed = 0;
    let remaining = this.buffer;

    while (remaining.length >= TDS_HEADER_LEN) {
      const pktLen = remaining.readUInt16BE(2);
      if (pktLen < TDS_HEADER_LEN || remaining.length < pktLen) break;

      const pktType = remaining.readUInt8(0);
      const pktStatus = remaining.readUInt8(1);

      if (msgType === null) msgType = pktType;

      payloads.push(remaining.subarray(TDS_HEADER_LEN, pktLen));
      consumed += pktLen;
      remaining = remaining.subarray(pktLen);

      if (pktStatus & STATUS_EOM) {
        this.buffer = remaining;
        return { type: msgType, payload: Buffer.concat(payloads) };
      }
    }

    return null;
  }
}

// ---------------------------------------------------------------------------
// TdsOverTlsDuplex - wraps/unwraps TDS headers around TLS handshake records
// ---------------------------------------------------------------------------

class TdsOverTlsDuplex extends Duplex {
  constructor(rawSocket, label) {
    super();
    this.rawSocket = rawSocket;
    this.label = label;
    this.pending = Buffer.alloc(0);
    this.handshakeMode = true;

    this._onData = (data) => {
      if (this.handshakeMode) {
        this.pending = Buffer.concat([this.pending, data]);
        this._drainTds();
      } else {
        this.push(data);
      }
    };

    this._onEnd = () => this.push(null);
    this._onError = (err) => this.destroy(err);

    rawSocket.on("data", this._onData);
    rawSocket.on("end", this._onEnd);
    rawSocket.on("error", this._onError);
  }

  switchToPassthrough() {
    log(this.label, "- switching to passthrough");
    this.handshakeMode = false;
    if (this.pending.length > 0) {
      log(this.label, "- flushing", this.pending.length, "pending bytes");
      this.push(this.pending);
      this.pending = Buffer.alloc(0);
    }
  }

  _drainTds() {
    while (this.pending.length >= TDS_HEADER_LEN) {
      const pktLen = this.pending.readUInt16BE(2);
      if (pktLen < TDS_HEADER_LEN || this.pending.length < pktLen) break;
      const payload = this.pending.subarray(TDS_HEADER_LEN, pktLen);
      this.pending = this.pending.subarray(pktLen);
      this.push(payload);
    }
  }

  _read() {}

  _write(chunk, _enc, cb) {
    if (this.handshakeMode) {
      const pkt = wrapTds(PKT.PRELOGIN, chunk);
      this.rawSocket.write(pkt, cb);
    } else {
      this.rawSocket.write(chunk, cb);
    }
  }

  _destroy(err, cb) {
    this.rawSocket.removeListener("data", this._onData);
    this.rawSocket.removeListener("end", this._onEnd);
    this.rawSocket.removeListener("error", this._onError);
    cb(err);
  }
}

// ---------------------------------------------------------------------------
// Self-signed certificate
// ---------------------------------------------------------------------------

function ensureSelfSignedCert() {
  const certDir = path.join(os.homedir(), ".azure-sql-proxy");
  const keyPath = path.join(certDir, "key.pem");
  const certPath = path.join(certDir, "cert.pem");

  if (fs.existsSync(certPath) && fs.existsSync(keyPath)) {
    return { key: fs.readFileSync(keyPath), cert: fs.readFileSync(certPath) };
  }

  if (!fs.existsSync(certDir)) {
    fs.mkdirSync(certDir, { recursive: true });
  }

  log("Generating self-signed TLS certificate...");
  execSync(
    `openssl req -x509 -newkey rsa:2048 -keyout "${keyPath}" -out "${certPath}" -days 3650 -nodes -subj "/CN=localhost"`,
    { stdio: "pipe" },
  );

  return { key: fs.readFileSync(keyPath), cert: fs.readFileSync(certPath) };
}

// ---------------------------------------------------------------------------
// Build login success response for the client
// ---------------------------------------------------------------------------

function buildLoginResponse(database) {
  const parts = [];

  // ENVCHANGE - Database
  const newDbBuf = Buffer.from(database, "utf16le");
  const envDbData = Buffer.alloc(1 + 1 + newDbBuf.length + 1);
  let o = 0;
  envDbData.writeUInt8(0x01, o++); // type = Database
  envDbData.writeUInt8(database.length, o++);
  newDbBuf.copy(envDbData, o);
  o += newDbBuf.length;
  envDbData.writeUInt8(0, o++); // empty old name

  const envDb = Buffer.alloc(3);
  envDb.writeUInt8(0xe3, 0);
  envDb.writeUInt16LE(envDbData.length, 1);
  parts.push(envDb, envDbData);

  // ENVCHANGE - Packet Size
  const newSizeBuf = Buffer.from("4096", "utf16le");
  const oldSizeBuf = Buffer.from("4096", "utf16le");
  const envPsData = Buffer.alloc(
    1 + 1 + newSizeBuf.length + 1 + oldSizeBuf.length,
  );
  o = 0;
  envPsData.writeUInt8(0x04, o++);
  envPsData.writeUInt8(4, o++);
  newSizeBuf.copy(envPsData, o);
  o += newSizeBuf.length;
  envPsData.writeUInt8(4, o++);
  oldSizeBuf.copy(envPsData, o);

  const envPs = Buffer.alloc(3);
  envPs.writeUInt8(0xe3, 0);
  envPs.writeUInt16LE(envPsData.length, 1);
  parts.push(envPs, envPsData);

  // LOGINACK
  const progName = "Microsoft SQL Server";
  const progBuf = Buffer.from(progName, "utf16le");
  const loginAckLen = 1 + 4 + 1 + progBuf.length + 4;
  const loginAck = Buffer.alloc(3 + loginAckLen);
  o = 0;
  loginAck.writeUInt8(0xad, o++);
  loginAck.writeUInt16LE(loginAckLen, o);
  o += 2;
  loginAck.writeUInt8(0x01, o++); // SQL_TSQL
  loginAck.writeUInt8(0x74, o++); // TDS 7.4 (big-endian)
  loginAck.writeUInt8(0x00, o++);
  loginAck.writeUInt8(0x00, o++);
  loginAck.writeUInt8(0x04, o++);
  loginAck.writeUInt8(progName.length, o++);
  progBuf.copy(loginAck, o);
  o += progBuf.length;
  loginAck.writeUInt8(16, o++);
  loginAck.writeUInt8(0, o++);
  loginAck.writeUInt8(0, o++);
  loginAck.writeUInt8(1, o++);
  parts.push(loginAck);

  // DONE
  const done = Buffer.alloc(13, 0);
  done.writeUInt8(0xfd, 0);
  parts.push(done);

  return wrapTds(PKT.TABULAR_RESULT, Buffer.concat(parts));
}

// ---------------------------------------------------------------------------
// Connection handler
//
// Strategy: Use tedious for the Azure connection (proven to work).
// After tedious connects, steal its cleartext TLS stream and pipe it
// to the client's TLS stream. Both sides send/receive TDS packets
// inside TLS, so the bridge is at the TDS level.
// ---------------------------------------------------------------------------

function handleConnection(clientSocket) {
  const clientAddr = clientSocket.remoteAddress + ":" + clientSocket.remotePort;
  log("Client connected:", clientAddr);

  let clientTlsSocket = null;
  let azureConn = null;
  let azureCleartext = null;
  let destroyed = false;

  function cleanup() {
    if (destroyed) return;
    destroyed = true;
    if (clientTlsSocket && !clientTlsSocket.destroyed)
      clientTlsSocket.destroy();
    if (azureConn) {
      try {
        azureConn.close();
      } catch {}
    }
    if (clientSocket && !clientSocket.destroyed) clientSocket.destroy();
    log("Cleaned up:", clientAddr);
  }

  clientSocket.on("error", (err) => {
    log("Client error:", err.message);
    cleanup();
  });

  clientSocket.on("close", () => cleanup());

  // =========================================================================
  // Phase 1: Client PRELOGIN
  // =========================================================================

  const clientReader = new TdsMessageReader();

  clientSocket.on("data", function onPrelogin(data) {
    clientReader.append(data);
    const msg = clientReader.tryReadMessage();
    if (!msg) return;

    clientSocket.removeListener("data", onPrelogin);

    if (msg.type !== PKT.PRELOGIN) {
      log("Expected PRELOGIN, got:", "0x" + msg.type.toString(16));
      cleanup();
      return;
    }

    log("Received client PRELOGIN");

    // Build a server PRELOGIN response telling client we support encryption
    const preloginResponse = buildPreloginResponse();
    clientSocket.write(wrapTds(PKT.TABULAR_RESULT, preloginResponse));

    phase2_clientTls();
  });

  // =========================================================================
  // Phase 2: TLS handshake with client (proxy acts as TLS server)
  // =========================================================================

  function phase2_clientTls() {
    clientSocket.removeAllListeners("data");

    const clientDuplex = new TdsOverTlsDuplex(clientSocket, "client-tls");
    const certOpts = ensureSelfSignedCert();

    clientTlsSocket = new tls.TLSSocket(clientDuplex, {
      isServer: true,
      key: certOpts.key,
      cert: certOpts.cert,
    });

    clientTlsSocket.on("secure", () => {
      log("Client TLS handshake complete");
      clientDuplex.switchToPassthrough();
      phase3_clientLogin7();
    });

    clientTlsSocket.on("error", (err) => {
      log("Client TLS error:", err.message);
      cleanup();
    });
  }

  // =========================================================================
  // Phase 3: Receive client Login7, extract database
  // =========================================================================

  function phase3_clientLogin7() {
    log("Waiting for client Login7...");

    const loginReader = new TdsMessageReader();

    clientTlsSocket.on("data", function onLogin(data) {
      loginReader.append(data);
      const msg = loginReader.tryReadMessage();
      if (!msg) return;

      clientTlsSocket.removeListener("data", onLogin);

      if (msg.type !== PKT.LOGIN7) {
        log("Expected LOGIN7, got:", "0x" + msg.type.toString(16));
        cleanup();
        return;
      }

      log("Received client LOGIN7");

      let database = CONFIG.database;
      if (msg.payload.length >= 94) {
        const ibDb = msg.payload.readUInt16LE(68);
        const cchDb = msg.payload.readUInt16LE(70);
        if (cchDb > 0 && ibDb + cchDb * 2 <= msg.payload.length) {
          const clientDb = msg.payload.toString(
            "utf16le",
            ibDb,
            ibDb + cchDb * 2,
          );
          if (clientDb) database = clientDb;
        }
      }
      log("Database:", database);

      phase4_connectAzure(database);
    });
  }

  // =========================================================================
  // Phase 4: Connect to Azure via tedious (handles all TDS/TLS/FEDAUTH)
  // =========================================================================

  function phase4_connectAzure(database) {
    let token;
    try {
      token = getAzureToken();
    } catch {
      cleanup();
      return;
    }

    log("Connecting to Azure SQL via tedious...");

    azureConn = new Connection({
      server: CONFIG.azureServer,
      authentication: {
        type: "azure-active-directory-access-token",
        options: { token },
      },
      options: {
        database,
        encrypt: true,
        port: CONFIG.azurePort,
        connectTimeout: 30000,
        requestTimeout: 0,
        packetSize: 4096,
      },
    });

    azureConn.on("connect", (err) => {
      if (err) {
        log("Azure connection error:", err.message);
        cleanup();
        return;
      }

      log("Connected to Azure SQL!");

      // Send login success to client
      const loginResponse = buildLoginResponse(database);
      clientTlsSocket.write(loginResponse);
      log("Sent login response to client");

      // Now steal tedious's cleartext TLS stream and bridge
      phase5_bridge(database);
    });

    azureConn.on("error", (err) => {
      log("Azure error:", err.message);
    });

    azureConn.connect();
  }

  // =========================================================================
  // Phase 5: Bridge client TLS <==> Azure tedious connection
  //
  // We intercept TDS messages from the client and execute them via tedious,
  // then relay the results back. This ensures tedious manages the Azure
  // connection state correctly.
  // =========================================================================

  function phase5_bridge(database) {
    log("Bridge mode active");

    const Request = require("tedious").Request;
    const bridgeReader = new TdsMessageReader();

    // tedious can only execute one request at a time.
    // Queue incoming messages and process them sequentially.
    const messageQueue = [];
    let busy = false;

    clientTlsSocket.on("data", (data) => {
      bridgeReader.append(data);
      let msg;
      while ((msg = bridgeReader.tryReadMessage()) !== null) {
        if (msg.type === 0x06) {
          // ATTENTION - cancel immediately, don't queue
          log("ATTENTION from client");
          azureConn.cancel();
        } else {
          messageQueue.push(msg);
          processQueue();
        }
      }
    });

    clientTlsSocket.on("end", cleanup);

    function processQueue() {
      if (busy || messageQueue.length === 0) return;
      busy = true;
      const msg = messageQueue.shift();
      handleClientMessage(msg, () => {
        busy = false;
        processQueue();
      });
    }

    function handleClientMessage(msg, done) {
      if (msg.type === 0x01) {
        handleSqlBatch(msg.payload, done);
      } else if (msg.type === 0x03) {
        handleRpcRequest(msg.payload, done);
      } else if (msg.type === 0x0e) {
        handleTransactionManager(msg.payload, done);
      } else {
        log("Unhandled TDS type:", "0x" + msg.type.toString(16));
        done();
      }
    }

    function handleSqlBatch(payload, queueDone) {
      // Extract SQL text (skip ALL_HEADERS)
      let offset = 0;
      if (payload.length >= 4) {
        const totalLen = payload.readUInt32LE(0);
        if (totalLen > 4 && totalLen <= payload.length) {
          offset = totalLen;
        }
      }
      const sql = payload.toString("utf16le", offset);
      log("SQL:", sql.substring(0, 120).replace(/[\r\n]+/g, " "));

      const responseChunks = [];

      const request = new Request(sql, (err, rowCount) => {
        log(
          "Request complete, err:",
          err ? err.message : "none",
          "rows:",
          rowCount,
          "chunks:",
          responseChunks.length,
        );
        if (err && responseChunks.length === 0) {
          sendErrorResponse(err);
        } else {
          const doneToken = Buffer.alloc(13, 0);
          doneToken.writeUInt8(0xfd, 0);
          if (rowCount > 0) {
            doneToken.writeUInt16LE(0x0010, 1); // DONE_COUNT
            doneToken.writeUInt32LE(rowCount & 0xffffffff, 5);
          }
          responseChunks.push(doneToken);
          sendTdsResponse(Buffer.concat(responseChunks));
        }
        queueDone();
      });

      request.on("columnMetadata", (columns) => {
        responseChunks.push(buildColMetadataToken(columns));
      });

      request.on("row", (columns) => {
        responseChunks.push(buildRowToken(columns));
      });

      request.on("error", (err) => {
        log("Query error:", err.message);
      });

      azureConn.execSqlBatch(request);
    }

    function handleRpcRequest(payload, queueDone) {
      log("RPC request received");
      sendErrorResponse({
        message:
          "RPC requests not yet supported by proxy. Use direct SQL queries.",
        number: 50000,
      });
      queueDone();
    }

    function handleTransactionManager(payload, queueDone) {
      if (payload.length < 8) {
        sendErrorResponse({
          message: "Invalid transaction request",
          number: 50000,
        });
        queueDone();
        return;
      }

      // Skip ALL_HEADERS
      let offset = 0;
      if (payload.length >= 4) {
        const headerLen = payload.readUInt32LE(0);
        if (headerLen > 4 && headerLen <= payload.length) offset = headerLen;
      }

      const requestType = payload.readUInt16LE(offset);
      log("Transaction request type:", requestType);

      const txnCommands = {
        1: "BEGIN TRANSACTION",
        2: "COMMIT",
        3: "ROLLBACK",
        4: "SAVE TRANSACTION",
      };
      const sql = txnCommands[requestType];

      if (!sql) {
        sendErrorResponse({
          message: "Unknown transaction type: " + requestType,
          number: 50000,
        });
        queueDone();
        return;
      }

      const request = new Request(sql, (err) => {
        if (err) {
          sendErrorResponse(err);
        } else {
          const doneToken = Buffer.alloc(13, 0);
          doneToken.writeUInt8(0xfd, 0);
          sendTdsResponse(doneToken);
        }
        queueDone();
      });

      azureConn.execSqlBatch(request);
    }

    function sendTdsResponse(tokenData) {
      log("Sending TDS response:", tokenData.length, "bytes");
      const pkt = wrapTds(PKT.TABULAR_RESULT, tokenData);
      if (clientTlsSocket && !clientTlsSocket.destroyed) {
        clientTlsSocket.write(pkt);
      }
    }

    function sendErrorResponse(err) {
      const msgBuf = Buffer.from(err.message || "Unknown error", "utf16le");
      const srvBuf = Buffer.from("azure-sql-proxy", "utf16le");
      const dataLen = 4 + 1 + 1 + 2 + msgBuf.length + 1 + srvBuf.length + 1 + 4;
      const errToken = Buffer.alloc(3 + dataLen);
      let o = 0;
      errToken.writeUInt8(0xaa, o++);
      errToken.writeUInt16LE(dataLen, o);
      o += 2;
      errToken.writeUInt32LE(err.number || 50000, o);
      o += 4;
      errToken.writeUInt8(1, o++);
      errToken.writeUInt8(16, o++);
      errToken.writeUInt16LE((err.message || "Unknown error").length, o);
      o += 2;
      msgBuf.copy(errToken, o);
      o += msgBuf.length;
      errToken.writeUInt8("azure-sql-proxy".length, o++);
      srvBuf.copy(errToken, o);
      o += srvBuf.length;
      errToken.writeUInt8(0, o++);
      errToken.writeUInt32LE(0, o);

      const done = Buffer.alloc(13, 0);
      done.writeUInt8(0xfd, 0);
      done.writeUInt16LE(0x0002, 1); // DONE_ERROR

      sendTdsResponse(Buffer.concat([errToken, done]));
    }
  }
}

// ---------------------------------------------------------------------------
// TDS Response Token builders
// ---------------------------------------------------------------------------

function buildColMetadataToken(columns) {
  const parts = [];
  const header = Buffer.alloc(3);
  header.writeUInt8(0x81, 0);
  header.writeUInt16LE(columns.length, 1);
  parts.push(header);

  for (const col of columns) {
    // UserType(4) + Flags(2)
    const prefix = Buffer.alloc(6, 0);
    prefix.writeUInt16LE(col.nullable ? 0x0001 : 0x0000, 4);
    parts.push(prefix);

    // TYPE_INFO: use NVARCHAR(MAX) for simplicity
    const typeInfo = Buffer.alloc(8);
    typeInfo.writeUInt8(0xe7, 0); // NVARCHAR
    typeInfo.writeUInt16LE(8000, 1); // max length
    typeInfo.writeUInt8(0x09, 3); // collation
    typeInfo.writeUInt8(0x04, 4);
    typeInfo.writeUInt8(0xd0, 5);
    typeInfo.writeUInt8(0x00, 6);
    typeInfo.writeUInt8(0x34, 7);
    parts.push(typeInfo);

    // Column name
    const name = col.colName || "";
    const nameBuf = Buffer.from(name, "utf16le");
    const nameLen = Buffer.alloc(1);
    nameLen.writeUInt8(name.length, 0);
    parts.push(nameLen, nameBuf);
  }

  return Buffer.concat(parts);
}

function buildRowToken(columns) {
  const parts = [Buffer.from([0xd1])];

  for (const col of columns) {
    const value = col.value;
    if (value === null || value === undefined) {
      parts.push(Buffer.from([0xff, 0xff])); // NULL
    } else {
      let strVal;
      if (value instanceof Date) {
        strVal = value.toISOString();
      } else if (typeof value === "object") {
        strVal = JSON.stringify(value);
      } else {
        strVal = String(value);
      }
      const encoded = Buffer.from(strVal, "utf16le");
      const lenBuf = Buffer.alloc(2);
      lenBuf.writeUInt16LE(encoded.length, 0);
      parts.push(lenBuf, encoded);
    }
  }

  return Buffer.concat(parts);
}

// ---------------------------------------------------------------------------
// PRELOGIN response builder
// ---------------------------------------------------------------------------

function buildPreloginResponse() {
  const options = [];

  // VERSION
  const ver = Buffer.alloc(6);
  ver.writeUInt8(16, 0);
  ver.writeUInt8(0, 1);
  ver.writeUInt16BE(4120, 2);
  ver.writeUInt16BE(0, 4);
  options.push({ token: 0x00, data: ver });

  // ENCRYPTION: ON (0x01)
  options.push({ token: 0x01, data: Buffer.from([0x01]) });

  // INSTOPT
  options.push({ token: 0x02, data: Buffer.from([0x00]) });

  // MARS: OFF
  options.push({ token: 0x04, data: Buffer.from([0x00]) });

  const headerSize = options.length * 5 + 1;
  const parts = [];
  let dataOffset = headerSize;

  for (const opt of options) {
    const hdr = Buffer.alloc(5);
    hdr.writeUInt8(opt.token, 0);
    hdr.writeUInt16BE(dataOffset, 1);
    hdr.writeUInt16BE(opt.data.length, 3);
    parts.push(hdr);
    dataOffset += opt.data.length;
  }

  parts.push(Buffer.from([0xff])); // terminator

  for (const opt of options) {
    parts.push(opt.data);
  }

  return Buffer.concat(parts);
}

// ---------------------------------------------------------------------------
// Utility
// ---------------------------------------------------------------------------

function log(...args) {
  if (CONFIG.verbose) {
    const ts = new Date().toISOString().substring(11, 23);
    console.log(`[${ts}]`, ...args);
  }
}

function parseArgs(argv) {
  const result = {};
  for (let i = 0; i < argv.length; i++) {
    if (argv[i].startsWith("--")) {
      const key = argv[i].slice(2);
      const next = argv[i + 1];
      if (next && !next.startsWith("--")) {
        result[key] = next;
        i++;
      } else {
        result[key] = true;
      }
    }
  }
  return result;
}

function printUsage() {
  console.log(`
azure-sql-proxy - Local proxy for Azure SQL with Entra ID (MFA) authentication

Usage:
  node index.js --server <azure-server> --database <database> [options]

Required:
  --server <host>        Azure SQL server (e.g. myserver.database.windows.net)
  --database <name>      Default database name

Options:
  --port <number>        Local port to listen on (default: 1433)
  --remote-port <number> Azure SQL port (default: 1433)
  --verbose              Enable verbose logging
  --help                 Show this help

How it works:
  1. Login to Azure: az login
  2. Start the proxy: node index.js --server myserver.database.windows.net --database mydb --verbose
  3. Connect TablePlus to 127.0.0.1:1433 (any username/password)
  `);
}

// ---------------------------------------------------------------------------
// Start
// ---------------------------------------------------------------------------

try {
  getAzureToken();
  console.log("Azure AD token acquired successfully.");
} catch {
  process.exit(1);
}

ensureSelfSignedCert();
console.log("TLS certificate ready.");

const server = net.createServer(handleConnection);

server.on("error", (err) => {
  if (err.code === "EADDRINUSE") {
    console.error(`Error: Port ${CONFIG.localPort} is already in use.`);
    process.exit(1);
  }
  console.error("Server error:", err.message);
});

server.listen(CONFIG.localPort, "127.0.0.1", () => {
  console.log(`
  azure-sql-proxy is running!

  Local:    127.0.0.1:${CONFIG.localPort}
  Remote:   ${CONFIG.azureServer}:${CONFIG.azurePort}
  Database: ${CONFIG.database}

  Connect your SQL client to 127.0.0.1:${CONFIG.localPort}
  User/Pass: anything (ignored)

  Press Ctrl+C to stop.
  `);
});

process.on("SIGINT", () => {
  console.log("\nShutting down...");
  server.close();
  process.exit(0);
});
