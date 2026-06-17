const crypto = require("crypto");
const GuacamoleLite = require("guacamole-lite");

const port = Number.parseInt(process.env.GUACAMOLE_WS_PORT || "30008", 10);
const guacdHost = process.env.GUACD_HOST || "127.0.0.1";
const guacdPort = Number.parseInt(process.env.GUACD_PORT || "4822", 10);

function encryptionKey() {
  const configured = process.env.GUACAMOLE_ENCRYPTION_KEY || "";
  if (/^[0-9a-fA-F]{64}$/.test(configured)) {
    return Buffer.from(configured, "hex");
  }
  if (configured.length === 32) {
    return Buffer.from(configured, "utf8");
  }
  const secret = process.env.SECRET_KEY || "change-this-secret-key";
  return crypto.createHash("sha256").update(`${secret}_guacamole`).digest();
}

const server = new GuacamoleLite(
  { port },
  { host: guacdHost, port: guacdPort },
  {
    crypt: {
      cypher: "AES-256-CBC",
      key: encryptionKey(),
    },
    log: {
      level: "ERRORS",
      stdLog: (...args) => console.log(...args),
      errorLog: (...args) => console.error(...args),
    },
    allowedUnencryptedConnectionSettings: {
      rdp: ["width", "height"],
      vnc: ["width", "height"],
      telnet: ["width", "height"],
    },
    connectionDefaultSettings: {
      rdp: {
        security: "any",
        "ignore-cert": true,
        "enable-wallpaper": true,
        "enable-font-smoothing": true,
        "enable-desktop-composition": false,
        "disable-audio": false,
        "enable-drive": false,
        "enable-gfx": true,
        "resize-method": "display-update",
        width: 1280,
        height: 720,
        dpi: 96,
        audio: ["audio/L16"],
      },
      vnc: {
        "swap-red-blue": false,
        cursor: "remote",
        security: "any",
        width: 1280,
        height: 720,
      },
      telnet: {
        "terminal-type": "xterm-256color",
      },
    },
  },
);

server.on("open", () => console.log("Guacamole connection opened"));
server.on("close", () => console.log("Guacamole connection closed"));
server.on("error", (_clientConnection, error) => console.error("Guacamole connection error", error));

console.log(`HomeLab Guacamole bridge listening on ${port}, guacd ${guacdHost}:${guacdPort}`);
