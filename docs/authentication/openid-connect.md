# OpenID Connect authentication

Kaya can act as an OpenID Connect (OIDC) relying party. Your identity provider authenticates the person; Kaya continues to decide whether the local account is active, which Kaya role it has, which modules it can access, and which application sessions exist.

OIDC is disabled by default. Existing local accounts, passwords, password reset, TOTP, roles and sessions continue to work.

## Requirements

Obtain these values from the identity provider:

- Issuer URL
- Client ID
- Client secret
- Support for Authorization Code flow, PKCE `S256`, OIDC discovery and an asymmetric ID-token signing algorithm

Register the callback URL shown in **Site Administration > Authentication > OpenID Connect**. Register the displayed post-logout redirect URL if provider logout will be enabled. Do not construct these URLs from a browser hostname; Kaya uses its configured public base URL.

The default scopes are:

```text
openid profile email
```

Kaya obtains authorization, token, JWKS, UserInfo and logout endpoints from `{issuer}/.well-known/openid-configuration`. Endpoint overrides are intentionally unsupported.

## Safe rollout

1. Keep the authentication mode set to **Local only**.
2. Choose an active local administrator in **Users**, ensure it has a strong local password, and mark it as an emergency local administrator.
3. Save the provider without enabling JIT provisioning, email matching or role synchronisation.
4. Select **Test configuration** and resolve every failure.
5. Select **Test OIDC login**. Review the sanitised email, name, subject, groups and proposed role.
6. Link the administrator under **My Profile > Sign-in methods**.
7. Change the mode to **Local and OIDC** and test a normal login in a private browser window.
8. Test `/auth/local` with the break-glass administrator.
9. Only then consider **OIDC preferred** or **OIDC required**.

OIDC-required mode is blocked until discovery and a real test login have succeeded, an active break-glass administrator with a local password exists, emergency local access is enabled, and the risk acknowledgement is selected.

## Claims

Default mappings are:

| Kaya value | OIDC claim |
| --- | --- |
| Email | `email` |
| Email verified | `email_verified` |
| Display name | `name` |
| First name | `given_name` |
| Last name | `family_name` |
| Preferred username | `preferred_username` |
| Groups | `groups` |

Dot notation is supported for nested values, such as `realm_access.roles` or `resource_access.kaya.roles`. The permanent identity is always the provider, issuer and `sub`; issuer and subject cannot be remapped.

Verified email is required by default. Allowed domains are exact and case-insensitive: `example.com` permits `person@example.com`, but not `person@fakeexample.com`.

## Roles

Enter exact mappings one per line:

```text
Kaya-Admins=admin
Kaya-Editors=editor
Kaya-Users=viewer
```

When multiple groups match, Kaya applies `admin > editor > viewer`. Unmatched newly provisioned accounts receive the configured default, which is `viewer`. Existing users keep their local role unless role synchronisation and per-user OIDC role management are both enabled. Kaya refuses to demote the last active administrator.

## Account linking and provisioning

Returning identities are resolved by issuer and subject, never repeatedly by email.

- A logged-in local user can link an identity under **My Profile > Sign-in methods**.
- An administrator can create a hashed, single-use, 30-minute linking invitation under **Account Links**.
- Email-based first-time matching is disabled by default. Confirmation mode requires the current local password; automatic matching must be explicitly acknowledged.
- JIT provisioning is disabled by default. JIT accounts have no local password and cannot use password reset or local TOTP.
- An OIDC-only account cannot unlink its last sign-in method. An administrator must first establish an approved local method or disable the account.

## Security behavior

- Authorization Code flow with PKCE `S256` is mandatory.
- State is single-use, nonce is validated, and temporary verifier/nonce data is encrypted in a short-lived server-side transaction.
- ID-token signature, asymmetric algorithm, issuer, audience, expiry, issued-at, nonce, subject and authorised party rules are validated with Authlib.
- Signing keys are cached briefly and refreshed once when validation indicates possible key rotation.
- Client secrets use Kaya's Fernet encryption and are never redisplayed.
- Authorization codes and callback query values are redacted from Uvicorn access logs.
- Issuers must use HTTPS except localhost development. Credentials, fragments, cloud metadata and link-local destinations are blocked. Private homelab addresses remain supported.
- Access and refresh tokens are not stored in the Kaya browser session.

## Provider examples

### Microsoft Entra ID

Use the tenant-specific v2 issuer, register Kaya as a web redirect URI, and request `openid profile email`. Group claims may require optional-token or enterprise-application configuration. This configuration is provided as guidance and is not a certification statement.

### Keycloak

Use the realm issuer, for example `https://sso.example.com/realms/homelab`. Configure a confidential client, standard flow, the exact Kaya callback, and a groups or realm-role mapper if Kaya role mapping is required.

### authentik

See [authentik setup](authentik.md).

## Troubleshooting

- **Issuer mismatch:** use the issuer exactly as advertised by discovery. A login hostname or authorization endpoint is not necessarily the issuer.
- **Callback mismatch:** copy the callback displayed by Kaya and verify the public base URL under Site Administration.
- **Invalid token:** verify client ID, provider clock, signing algorithm, JWKS reachability and proxy TLS handling.
- **Account not authorised:** link the local user, deliberately enable approved email matching, or deliberately enable JIT provisioning.
- **Missing groups:** add the provider's groups claim/scope and set the correct claim path.
- **Private CA:** install the CA in the container trust store where possible. Disabling TLS verification requires explicit acknowledgement and remains visibly warned.
- **Provider outage:** use `/auth/local` with a designated break-glass administrator.

Reverse proxies must preserve HTTPS scheme information and Kaya's configured public base URL must match the address registered with the provider. Use HTTPS for every non-local deployment.
