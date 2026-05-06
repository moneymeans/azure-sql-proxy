#!/usr/bin/env node

"use strict";

const net = require("net");
const tls = require("tls");
const { execFile, execFileSync } = require("child_process");
const { promisify } = require("util");
const fs = require("fs");
const path = require("path");
const os = require("os");
const crypto = require("crypto");
const { Duplex } = require("stream");
const { Connection } = require("tedious");
const { versions: TDS_VERSIONS } = require("tedious/lib/tds-versions");

const execFileAsync = promisify(execFile);

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

// --server and --database are now optional defaults: the proxy reads the
// ServerName / Database fields from the client's LOGIN7 packet and uses those
// when present, falling back to the CLI flags.

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
const STATUS_NORMAL = 0x00;
// TDS packet length is a uint16, so payload per packet is capped at
// 65535 - TDS_HEADER_LEN. We use a smaller value matching the LOGIN7
// negotiated packetSize (4096) to stay compatible with strict clients.
const MAX_PACKET_PAYLOAD = 4096 - TDS_HEADER_LEN;

// ---------------------------------------------------------------------------
// Azure Token Cache
// ---------------------------------------------------------------------------

let cachedToken = null;
let tokenExpiresAt = 0;
let inFlightRefresh = null;

async function getAzureToken() {
  const now = Date.now();
  if (cachedToken && tokenExpiresAt - now > 5 * 60 * 1000) {
    return cachedToken;
  }
  if (inFlightRefresh) return inFlightRefresh;

  inFlightRefresh = (async () => {
    log("Acquiring Azure AD token via az cli...");
    try {
      const { stdout } = await execFileAsync(
        "az",
        [
          "account",
          "get-access-token",
          "--resource",
          "https://database.windows.net/",
          "--output",
          "json",
        ],
        { timeout: 30000 },
      );
      const parsed = JSON.parse(stdout);
      cachedToken = parsed.accessToken;
      tokenExpiresAt = parsed.expires_on * 1000;
      log("Token acquired, expires", new Date(tokenExpiresAt).toISOString());
      return cachedToken;
    } catch (err) {
      console.error("Failed to get Azure token. Run `az login` first.");
      throw err;
    } finally {
      inFlightRefresh = null;
    }
  })();

  return inFlightRefresh;
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

// Splits a large payload across multiple TDS packets. Each non-final packet
// has STATUS_NORMAL; the final one has STATUS_EOM. Packet IDs increment
// modulo 256.
function wrapTdsChunked(type, payload) {
  if (payload.length <= MAX_PACKET_PAYLOAD) return wrapTds(type, payload);
  const chunks = [];
  let offset = 0;
  let pktId = 1;
  while (offset < payload.length) {
    const end = Math.min(offset + MAX_PACKET_PAYLOAD, payload.length);
    const slice = payload.subarray(offset, end);
    const isLast = end === payload.length;
    const hdr = Buffer.alloc(TDS_HEADER_LEN);
    hdr.writeUInt8(type, 0);
    hdr.writeUInt8(isLast ? STATUS_EOM : STATUS_NORMAL, 1);
    hdr.writeUInt16BE(TDS_HEADER_LEN + slice.length, 2);
    hdr.writeUInt16BE(0, 4);
    hdr.writeUInt8(pktId & 0xff, 6);
    hdr.writeUInt8(0, 7);
    chunks.push(hdr, slice);
    offset = end;
    pktId++;
  }
  return Buffer.concat(chunks);
}

// Reads the leading ALL_HEADERS section length from a SQL_BATCH /
// TRANSACTION_MANAGER payload. Returns the offset where the rest of the
// payload starts, or -1 if the header is malformed.
function parseAllHeaders(payload) {
  if (payload.length < 4) return -1;
  const totalLen = payload.readUInt32LE(0);
  if (totalLen < 4 || totalLen > payload.length) return -1;
  return totalLen;
}

// Reads a UTF-16LE string field from a LOGIN7 payload. `fieldOffset` is the
// offset of the (ibField, cchField) pair (each uint16-LE; cchField is char
// count, not byte count). Returns "" if the field is absent or malformed.
function readLogin7String(payload, fieldOffset) {
  if (payload.length < fieldOffset + 4) return "";
  const ib = payload.readUInt16LE(fieldOffset);
  const cch = payload.readUInt16LE(fieldOffset + 2);
  if (cch === 0) return "";
  const end = ib + cch * 2;
  if (ib < 0 || end > payload.length) return "";
  return payload.toString("utf16le", ib, end);
}

function isValidAzureSqlHost(host) {
  return /^[A-Za-z0-9.-]+\.database\.windows\.net$/i.test(host);
}

// Builds a TDS TABULAR_RESULT packet containing an ERROR token followed by a
// DONE_ERROR token. Suitable for both pre-login-success failures and
// mid-session error replies.
function buildErrorPacket(message, number = 50000) {
  const text = message || "Unknown error";
  const msgBuf = Buffer.from(text, "utf16le");
  const srvName = "azure-sql-proxy";
  const srvBuf = Buffer.from(srvName, "utf16le");
  const dataLen = 4 + 1 + 1 + 2 + msgBuf.length + 1 + srvBuf.length + 1 + 4;
  const errToken = Buffer.alloc(3 + dataLen);
  let o = 0;
  errToken.writeUInt8(0xaa, o++);
  errToken.writeUInt16LE(dataLen, o);
  o += 2;
  errToken.writeUInt32LE(number, o);
  o += 4;
  errToken.writeUInt8(1, o++); // state
  errToken.writeUInt8(16, o++); // class (>= 11 = error)
  errToken.writeUInt16LE(text.length, o);
  o += 2;
  msgBuf.copy(errToken, o);
  o += msgBuf.length;
  errToken.writeUInt8(srvName.length, o++);
  srvBuf.copy(errToken, o);
  o += srvBuf.length;
  errToken.writeUInt8(0, o++); // line number length
  errToken.writeUInt32LE(0, o); // line number

  const done = Buffer.alloc(13, 0);
  done.writeUInt8(0xfd, 0);
  done.writeUInt16LE(0x0002, 1); // DONE_ERROR

  return wrapTds(PKT.TABULAR_RESULT, Buffer.concat([errToken, done]));
}

function sendLoginError(socket, message) {
  if (!socket || socket.destroyed) return;
  try {
    socket.write(buildErrorPacket(message));
  } catch (err) {
    warn("Failed to send login error:", err.message);
  }
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
    fs.mkdirSync(certDir, { recursive: true, mode: 0o700 });
  }

  log("Generating self-signed TLS certificate...");
  try {
    execFileSync(
      "openssl",
      [
        "req",
        "-x509",
        "-newkey",
        "rsa:2048",
        "-keyout",
        keyPath,
        "-out",
        certPath,
        "-days",
        "3650",
        "-nodes",
        "-subj",
        "/CN=localhost",
      ],
      { stdio: "pipe" },
    );
  } catch (err) {
    console.error(
      "Failed to generate TLS certificate via openssl. Ensure openssl is installed and on PATH.",
    );
    throw err;
  }

  // Tighten key file permissions to owner-read/write only.
  try {
    fs.chmodSync(keyPath, 0o600);
  } catch (err) {
    log("Could not chmod key file:", err.message);
  }

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
  info("Client connected:", clientAddr);

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
    info("Cleaned up:", clientAddr);
  }

  clientSocket.on("error", (err) => {
    warn("Client error:", err.message);
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
      warn("Expected PRELOGIN, got:", "0x" + msg.type.toString(16));
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
      warn("Client TLS error:", err.message);
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
        warn("Expected LOGIN7, got:", "0x" + msg.type.toString(16));
        cleanup();
        return;
      }

      log("Received client LOGIN7");

      const clientServer = readLogin7String(msg.payload, 52);
      const clientDatabase = readLogin7String(msg.payload, 68);

      // Use the client's LOGIN7 server name only if it looks like an Azure SQL
      // host. Clients commonly send the proxy's address (e.g. 127.0.0.1:11433)
      // there, which we should ignore in favour of --server.
      const clientServerIsAzure =
        clientServer && isValidAzureSqlHost(clientServer);
      const server = clientServerIsAzure ? clientServer : CONFIG.azureServer;
      const database = clientDatabase || CONFIG.database;

      if (!server) {
        warn("No Azure server configured (client sent:", clientServer || "<empty>", ")");
        sendLoginError(
          clientTlsSocket,
          "azure-sql-proxy: no Azure SQL server configured. Pass --server <host>.database.windows.net to the proxy.",
        );
        cleanup();
        return;
      }
      if (!isValidAzureSqlHost(server)) {
        warn("Rejecting non-Azure server:", server);
        sendLoginError(
          clientTlsSocket,
          `azure-sql-proxy: refusing to connect to '${server}'. Server must end with .database.windows.net.`,
        );
        cleanup();
        return;
      }
      if (!database) {
        warn("No database provided by client or via --database");
        sendLoginError(
          clientTlsSocket,
          "azure-sql-proxy: no database configured. Set the database in your client, or pass --database to the proxy.",
        );
        cleanup();
        return;
      }

      info("Server:", server, "Database:", database);
      phase4_connectAzure(server, database);
    });
  }

  // =========================================================================
  // Phase 4: Connect to Azure via tedious (handles all TDS/TLS/FEDAUTH)
  // =========================================================================

  async function phase4_connectAzure(server, database) {
    let token;
    try {
      token = await getAzureToken();
    } catch {
      cleanup();
      return;
    }
    if (destroyed) return;

    log("Connecting to Azure SQL via tedious...");

    azureConn = new Connection({
      server,
      authentication: {
        type: "azure-active-directory-access-token",
        options: { token },
      },
      options: {
        database,
        encrypt: true,
        port: CONFIG.azurePort,
        connectTimeout: 30000,
        requestTimeout: 60000,
        packetSize: 4096,
      },
    });

    azureConn.on("connect", (err) => {
      if (err) {
        warn("Azure connection error:", err.message);
        cleanup();
        return;
      }

      info("Connected to Azure SQL");

      // Send login success to client
      const loginResponse = buildLoginResponse(database);
      clientTlsSocket.write(loginResponse);
      log("Sent login response to client");

      // Now steal tedious's cleartext TLS stream and bridge
      phase5_bridge(database);
    });

    azureConn.on("error", (err) => {
      warn("Azure error:", err.message);
      cleanup();
    });

    azureConn.on("end", () => {
      log("Azure connection ended");
      cleanup();
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
    const MAX_QUEUE = 32;
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
        } else if (messageQueue.length >= MAX_QUEUE) {
          log("Queue full, rejecting message of type", "0x" + msg.type.toString(16));
          sendErrorResponse({
            message: `azure-sql-proxy: too many pending requests (cap=${MAX_QUEUE})`,
            number: 50000,
          });
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
      // Skip ALL_HEADERS. The first uint32-LE is the total header length.
      const offset = parseAllHeaders(payload);
      if (offset === -1) {
        sendErrorResponse({
          message: "Malformed SQL_BATCH ALL_HEADERS",
          number: 50000,
        });
        queueDone();
        return;
      }
      const sql = payload.toString("utf16le", offset);
      log("SQL:", sql.substring(0, 120).replace(/[\r\n]+/g, " "));

      const responseChunks = [];
      const startedAt = Date.now();

      const request = new Request(sql, (err, rowCount) => {
        const ms = Date.now() - startedAt;
        if (err) {
          warn(`Query failed (${ms}ms):`, err.message);
        } else {
          info(`Query ok (${ms}ms, ${rowCount} rows)`);
        }
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
        log("Query error event:", err.message);
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
      const offset = parseAllHeaders(payload);
      if (offset === -1 || payload.length < offset + 2) {
        sendErrorResponse({
          message: "Malformed transaction request",
          number: 50000,
        });
        queueDone();
        return;
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
      const pkt = wrapTdsChunked(PKT.TABULAR_RESULT, tokenData);
      if (clientTlsSocket && !clientTlsSocket.destroyed) {
        clientTlsSocket.write(pkt);
      }
    }

    function sendErrorResponse(err) {
      const pkt = buildErrorPacket(
        err.message || "Unknown error",
        err.number || 50000,
      );
      if (clientTlsSocket && !clientTlsSocket.destroyed) {
        clientTlsSocket.write(pkt);
      }
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

    // TYPE_INFO: NVARCHAR(MAX). Max length 0xFFFF = PARTLENTYPE.
    const typeInfo = Buffer.alloc(8);
    typeInfo.writeUInt8(0xe7, 0); // NVARCHAR
    typeInfo.writeUInt16LE(0xffff, 1); // PARTLENTYPE
    typeInfo.writeUInt8(0x09, 3); // collation: SQL_Latin1_General_CP1_CI_AS
    typeInfo.writeUInt8(0x04, 4);
    typeInfo.writeUInt8(0xd0, 5);
    typeInfo.writeUInt8(0x00, 6);
    typeInfo.writeUInt8(0x34, 7);
    parts.push(typeInfo);

    // Column name (B_VARCHAR: 1-byte char count, max 255).
    const rawName = col.colName || "";
    const name =
      rawName.length > 255 ? rawName.substring(0, 255) : rawName;
    const nameBuf = Buffer.from(name, "utf16le");
    const nameLen = Buffer.alloc(1);
    nameLen.writeUInt8(name.length, 0);
    parts.push(nameLen, nameBuf);
  }

  return Buffer.concat(parts);
}

const PLP_NULL = Buffer.from([0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
const PLP_UNKNOWN_LEN = Buffer.from([
  0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
]);
const PLP_TERMINATOR = Buffer.from([0x00, 0x00, 0x00, 0x00]);
const PLP_CHUNK_SIZE = 8000; // bytes per chunk, must fit in uint32 (and well within)

function encodePlpValue(encoded) {
  // Length prefix: actual byte length (fits in uint64 for any realistic value).
  const lenBuf = Buffer.alloc(8);
  lenBuf.writeBigUInt64LE(BigInt(encoded.length), 0);

  const chunks = [lenBuf];
  for (let i = 0; i < encoded.length; i += PLP_CHUNK_SIZE) {
    const slice = encoded.subarray(i, i + PLP_CHUNK_SIZE);
    const chunkLen = Buffer.alloc(4);
    chunkLen.writeUInt32LE(slice.length, 0);
    chunks.push(chunkLen, slice);
  }
  chunks.push(PLP_TERMINATOR);
  return Buffer.concat(chunks);
}

function buildRowToken(columns) {
  const parts = [Buffer.from([0xd1])];

  for (const col of columns) {
    const value = col.value;
    if (value === null || value === undefined) {
      parts.push(PLP_NULL);
      continue;
    }

    let strVal;
    if (value instanceof Date) {
      strVal = value.toISOString();
    } else if (typeof value === "object") {
      strVal = JSON.stringify(value);
    } else {
      strVal = String(value);
    }
    const encoded = Buffer.from(strVal, "utf16le");
    parts.push(encodePlpValue(encoded));
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

function info(...args) {
  const ts = new Date().toISOString().substring(11, 23);
  console.log(`[${ts}]`, ...args);
}

function warn(...args) {
  const ts = new Date().toISOString().substring(11, 23);
  console.error(`[${ts}]`, ...args);
}

function parseArgs(argv) {
  const KNOWN_FLAGS = {
    port: "value",
    server: "value",
    "remote-port": "value",
    database: "value",
    verbose: "boolean",
    help: "boolean",
  };
  const result = {};
  for (let i = 0; i < argv.length; i++) {
    const tok = argv[i];
    if (!tok.startsWith("--")) {
      console.error(`Error: unexpected positional argument '${tok}'.`);
      process.exit(1);
    }
    const key = tok.slice(2);
    const kind = KNOWN_FLAGS[key];
    if (!kind) {
      console.error(`Error: unknown flag '--${key}'.`);
      process.exit(1);
    }
    if (kind === "boolean") {
      result[key] = true;
      continue;
    }
    const next = argv[i + 1];
    if (next === undefined || next.startsWith("--")) {
      console.error(`Error: flag '--${key}' requires a value.`);
      process.exit(1);
    }
    if (Object.prototype.hasOwnProperty.call(result, key)) {
      console.error(`Error: flag '--${key}' specified more than once.`);
      process.exit(1);
    }
    result[key] = next;
    i++;
  }
  return result;
}

function printUsage() {
  console.log(`
azure-sql-proxy - Local proxy for Azure SQL with Entra ID (MFA) authentication

Usage:
  node index.js --server <host> [options]

Options:
  --server <host>        Default Azure SQL server (e.g. myserver.database.windows.net).
                         If a client sends a different host in its LOGIN7 packet
                         (must end with .database.windows.net), the proxy uses
                         that instead.
  --database <name>      Default database name. Optional: most clients (TablePlus,
                         DBeaver, etc.) send the database in their LOGIN7 packet,
                         and the proxy uses that, so you usually don't need this.
  --port <number>        Local port to listen on (default: 1433).
  --remote-port <number> Azure SQL port (default: 1433).
  --verbose              Enable verbose logging.
  --help                 Show this help.

How it works:
  1. Login to Azure: az login
  2. Start the proxy: node index.js --server myserver.database.windows.net --verbose
  3. In TablePlus, set Host=127.0.0.1, Port=1433, Database=your db,
     User/Pass=anything.
  `);
}

// ---------------------------------------------------------------------------
// Start
// ---------------------------------------------------------------------------

async function main() {
  try {
    await getAzureToken();
    console.log("Azure AD token acquired successfully.");
  } catch {
    process.exit(1);
  }

  ensureSelfSignedCert();
  console.log("TLS certificate ready.");

  const activeConnections = new Set();
  const server = net.createServer((socket) => {
    activeConnections.add(socket);
    socket.on("close", () => activeConnections.delete(socket));
    handleConnection(socket);
  });

  server.on("error", (err) => {
    if (err.code === "EADDRINUSE") {
      console.error(`Error: Port ${CONFIG.localPort} is already in use.`);
      process.exit(1);
    }
    console.error("Server error:", err.message);
  });

  server.listen(CONFIG.localPort, "127.0.0.1", () => {
    const remote = CONFIG.azureServer
      ? `${CONFIG.azureServer}:${CONFIG.azurePort}`
      : "(read from client LOGIN7)";
    const db = CONFIG.database || "(read from client LOGIN7)";
    console.log(`
  azure-sql-proxy is running!

  Local:    127.0.0.1:${CONFIG.localPort}
  Remote:   ${remote}
  Database: ${db}

  Connect your SQL client to 127.0.0.1:${CONFIG.localPort}
  User/Pass: anything (ignored)

  Press Ctrl+C to stop.
    `);
  });

  let shuttingDown = false;
  process.on("SIGINT", () => {
    if (shuttingDown) {
      console.log("\nForcing immediate exit.");
      process.exit(1);
    }
    shuttingDown = true;
    console.log("\nShutting down...");
    server.close();
    const drainCap = setTimeout(() => {
      console.log(
        `Drain timed out with ${activeConnections.size} connection(s) still open; forcing exit.`,
      );
      for (const sock of activeConnections) sock.destroy();
      process.exit(0);
    }, 5000);
    drainCap.unref();
    const checkDrained = setInterval(() => {
      if (activeConnections.size === 0) {
        clearInterval(checkDrained);
        clearTimeout(drainCap);
        process.exit(0);
      }
    }, 100);
    checkDrained.unref();
  });
}

main().catch((err) => {
  console.error("Fatal:", err);
  process.exit(1);
});
