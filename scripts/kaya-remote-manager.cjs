const { WebSocket, WebSocketServer } = require("ws");
const { Client } = require("ssh2");
const crypto = require("crypto");

const port = Number.parseInt(process.env.KAYA_REMOTE_WS_PORT || process.env.HOMELAB_REMOTE_WS_PORT || "30009", 10);
const bindHost = process.env.KAYA_REMOTE_WS_HOST || process.env.HOMELAB_REMOTE_WS_HOST || "127.0.0.1";

const UTF8_ENV = {
  TERM: "xterm-256color",
  COLORTERM: "truecolor",
  FORCE_COLOR: "1",
  CLICOLOR: "1",
  CLICOLOR_FORCE: "1",
};

function send(ws, payload) {
  if (ws.readyState === WebSocket.OPEN) {
    ws.send(JSON.stringify(payload));
  }
}

function cleanup(conn, stream) {
  try {
    if (stream) stream.end();
  } catch (_error) {
    // ignore shutdown errors
  }
  try {
    if (conn) conn.end();
  } catch (_error) {
    // ignore shutdown errors
  }
}

function startShell(ws, conn, data) {
  const rows = Number.parseInt(data.rows || "34", 10);
  const cols = Number.parseInt(data.cols || "120", 10);
  const env = { ...UTF8_ENV, ...(data.env || {}) };

  conn.shell({ term: "xterm-256color", rows, cols }, { env }, (error, stream) => {
    if (error) {
      send(ws, { type: "error", message: `SSH shell failed: ${error.message}` });
      cleanup(conn, null);
      return;
    }

    send(ws, { type: "connected", message: "Connected" });

    stream.on("data", (chunk) => {
      send(ws, { type: "data", data: chunk.toString("utf8") });
    });
    stream.stderr?.on("data", (chunk) => {
      send(ws, { type: "data", data: chunk.toString("utf8") });
    });
    stream.on("close", () => {
      send(ws, { type: "closed", message: "SSH session closed" });
      cleanup(conn, null);
      ws.close();
    });

    ws.on("message", (raw) => {
      let message;
      try {
        message = JSON.parse(raw.toString());
      } catch (_error) {
        return;
      }

      if (message.type === "input" && typeof message.data === "string") {
        stream.write(Buffer.from(message.data, "utf8"));
        return;
      }

      if (message.type === "resize" && message.data) {
        const nextCols = Number.parseInt(message.data.cols || cols, 10);
        const nextRows = Number.parseInt(message.data.rows || rows, 10);
        stream.setWindow(nextRows, nextCols, nextRows, nextCols);
        return;
      }

      if (message.type === "disconnect") {
        cleanup(conn, stream);
        ws.close();
      }
    });

    ws.on("close", () => cleanup(conn, stream));
  });
}

const server = new WebSocketServer({ host: bindHost, port });

server.on("connection", (ws) => {
  let conn = null;

  ws.once("message", (raw) => {
    let message;
    try {
      message = JSON.parse(raw.toString());
    } catch (_error) {
      send(ws, { type: "error", message: "Invalid SSH connection request" });
      ws.close();
      return;
    }

    if (message.type !== "connectToHost" || !message.data) {
      send(ws, { type: "error", message: "Missing SSH host configuration" });
      ws.close();
      return;
    }

    const data = message.data;
    const expectedAlgorithm = String(data.hostKeyAlgorithm || "");
    const expectedFingerprint = String(data.hostKeyFingerprint || "");
    if (!expectedAlgorithm || !expectedFingerprint.startsWith("SHA256:")) {
      send(ws, { type: "error", message: "SSH host identity is not enrolled" });
      ws.close();
      return;
    }
    const verifyHostKey = (key) => {
      const actual = `SHA256:${crypto.createHash("sha256").update(key).digest("base64").replace(/=+$/, "")}`;
      const actualBuffer = Buffer.from(actual, "utf8");
      const expectedBuffer = Buffer.from(expectedFingerprint, "utf8");
      return actualBuffer.length === expectedBuffer.length && crypto.timingSafeEqual(actualBuffer, expectedBuffer);
    };
    const algorithms = { ...(data.algorithms || {}), serverHostKey: [expectedAlgorithm] };
    conn = new Client();
    conn
      .on("ready", () => startShell(ws, conn, data))
      .on("error", (error) => {
        send(ws, { type: "error", message: `SSH connection failed: ${error.message}` });
        ws.close();
      })
      .on("close", () => {
        if (ws.readyState === WebSocket.OPEN) {
          send(ws, { type: "closed", message: "SSH connection closed" });
          ws.close();
        }
      })
      .connect({
        host: data.host,
        port: Number.parseInt(data.port || "22", 10),
        username: data.username,
        password: data.password,
        keepaliveInterval: 30000,
        keepaliveCountMax: 3,
        readyTimeout: 15000,
        tryKeyboard: true,
        algorithms,
        hostVerifier: verifyHostKey,
      });
  });

  ws.on("close", () => cleanup(conn, null));
});

console.log(`Kaya Remote Manager SSH service listening on ${bindHost}:${port}`);
