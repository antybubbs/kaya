# Secure Send

Secure Send provides temporary encrypted delivery of files and secure notes. It complements Secret Vault: Vault content is permanent encrypted storage, while a Secure Send package is destroyed when it expires or is deleted.

## Deployment

The existing `docker-compose.yml` starts both Kaya and the lightweight `secure-send-gateway` from the same Kaya image. Both use the existing database, application encryption key, SMTP configuration and `data` volume. No second repository, administration interface or configuration file is required.

Expose the main Kaya port only to trusted users. Publish the Secure Send gateway port (`KAYA_SECURE_SEND_PORT`, default `8999`) for recipients and configure its public origin in **Site Administration → Module Settings → Secure Send**. The gateway exposes only recipient unlock, download, logout, health and static-asset routes; it has no Kaya login or administrative routes.

## Security model

- Each package has a random AES-256-GCM content key and a high-entropy URL token.
- The package key is wrapped using material derived from the URL token, sender PIN and generated ten-word passphrase. The credential material is also protected with Kaya's Argon2 password hashing.
- File bodies, notes, filenames, content types, package descriptions and recipient display details are encrypted at rest.
- Recipient sessions use opaque, hashed database tokens, a separate CSRF token, a 15-minute idle timeout and immediate revocation.
- The gateway accepts only exact token-shaped routes, expected HTTP methods, same-origin form submissions, bounded form bodies and the configured public hostname. Malformed, unknown, expired and revoked paths receive the same unbranded `403 Forbidden` response.
- Only three dedicated static assets are exposed. The health endpoint requires an application-secret-derived proof used by Kaya's internal status check.
- Gateway access logging and server fingerprint headers are disabled so bearer URL factors are not written by Uvicorn.
- Expiry, revocation, deletion and one-download completion revoke active sessions. Expiry and deletion remove encrypted payload files and secure-note ciphertext while retaining minimal encrypted lifecycle metadata for sender history and audit correlation.
- Administrators can manage package lifecycle but the Kaya UI does not expose package content or recipient details for packages they did not send.
- Recipient links may be sent through Kaya SMTP, but PINs and passphrases are never included. The generated passphrase is shown to the sender once.

Back up Kaya's persistent encryption key together with normal operational recovery material. A database or file-volume backup without that key cannot decrypt Secure Send data. Restoring an old backup does not make already-expired packages accessible: both the gateway and cleanup worker enforce the stored expiry before serving content.

The Secure Send URL token is one of three required factors and must still be treated as sensitive. Configure any reverse proxy, WAF, CDN and upstream load balancer not to record full Secure Send request paths, or to redact the 64-character token segment. Kaya can suppress its own gateway access log but cannot control logging performed by infrastructure in front of it. HTTPS is mandatory for public deployment.

## Operation

Admins and editors can create packages under **Security → Secure Send**. Internal recipients see active deliveries under **Received** and may save a separate encrypted copy into an already-unlocked Secret Vault when the sender permits it. Vault owners can use **Share securely** on a Vault item to create a temporary, independent Secure Send copy.

Secure Send is visible but non-functional in Kaya's public demo. The public gateway returns a generic not-found response in demo mode.
