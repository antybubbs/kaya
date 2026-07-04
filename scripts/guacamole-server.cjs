const crypto = require("crypto");
const GuacamoleLite = require("guacamole-lite");
const Crypt = require("guacamole-lite/lib/Crypt.js");

const port = Number.parseInt(process.env.GUACAMOLE_WS_PORT || "30008", 10);
const guacdHost = process.env.GUACD_HOST || "127.0.0.1";
const guacdPort = Number.parseInt(process.env.GUACD_PORT || "4822", 10);

function base64UrlDecode(value) {
  const padded = value.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(value.length / 4) * 4, "=");
  return Buffer.from(padded, "base64");
}

function fernetKey() {
  const configured = process.env.ENCRYPTION_KEY || "";
  const key = base64UrlDecode(configured);
  if (key.length !== 32) {
    throw new Error("ENCRYPTION_KEY must be a valid Fernet key");
  }
  return {
    signing: key.subarray(0, 16),
    encryption: key.subarray(16),
  };
}

function timingSafeEqual(left, right) {
  return left.length === right.length && crypto.timingSafeEqual(left, right);
}

function decryptFernetToken(token) {
  const key = fernetKey();
  const decoded = base64UrlDecode(token);
  if (decoded.length < 73 || decoded[0] !== 0x80) {
    throw new Error("Invalid Fernet token");
  }

  const signedPayload = decoded.subarray(0, decoded.length - 32);
  const suppliedMac = decoded.subarray(decoded.length - 32);
  const expectedMac = crypto.createHmac("sha256", key.signing).update(signedPayload).digest();
  if (!timingSafeEqual(suppliedMac, expectedMac)) {
    throw new Error("Invalid Fernet token signature");
  }

  const iv = decoded.subarray(9, 25);
  const ciphertext = decoded.subarray(25, decoded.length - 32);
  const decipher = crypto.createDecipheriv("aes-128-cbc", key.encryption, iv);
  const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  return JSON.parse(plaintext.toString("utf8"));
}

Crypt.prototype.decrypt = function decrypt(encodedString) {
  return decryptFernetToken(encodedString);
};
GuacamoleLite.prototype.decryptToken = function decryptToken(encryptedToken) {
  return decryptFernetToken(encryptedToken);
};

const server = new GuacamoleLite(
  { port },
  { host: guacdHost, port: guacdPort },
  {
    crypt: {
      cypher: "FERNET",
      key: Buffer.alloc(32),
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
        // Prefer the classic bitmap pipeline for reliable sessions across
        // VPN and offsite links. Per-connection settings may still opt in.
        "enable-gfx": false,
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

console.log(`Kaya Guacamole bridge listening on ${port}, guacd ${guacdHost}:${guacdPort}`);
