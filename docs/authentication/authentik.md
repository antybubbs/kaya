# Configure authentik for Kaya

Kaya uses standard OpenID Connect behavior and does not make authentik-specific API calls.

## Create the provider and application

1. In authentik, create an **OAuth2/OpenID Provider** for Kaya.
2. Select an Authorization Code flow and use a confidential client.
3. Copy the client ID and client secret.
4. Add the exact callback URL displayed in **Kaya > Site Administration > Authentication > OpenID Connect**.
5. If provider logout is required, add Kaya's displayed post-logout redirect URL.
6. Create an authentik application and attach the provider.

Use the issuer shown by authentik for the application, commonly similar to:

```text
https://auth.example.com/application/o/kaya/
```

Do not enter the authorize, token or discovery endpoint. Kaya discovers those endpoints from the issuer.

## Scopes and claims

Request:

```text
openid profile email
```

Ensure the flow exposes `email`, `email_verified`, `given_name`, `family_name` and `preferred_username` as needed.

For group-based roles, add an authentik scope mapping that returns a string array in a claim such as `groups`. In Kaya, map exact group names under **Claim & Role Mapping**, for example:

```text
Kaya Admins=admin
Kaya Editors=editor
Kaya Users=viewer
```

Do not grant administrator access until a sanitised test login shows the expected group claim.

## Link the first administrator safely

1. Leave Kaya in **Local only** mode.
2. Mark one active local administrator with a usable local password as break glass.
3. Save the authentik provider.
4. Run **Test configuration**.
5. Run **Test OIDC login** and review the resolved identity and role.
6. Sign in locally, open **My Profile > Sign-in methods**, and link the authentik identity.
7. Switch Kaya to **Local and OIDC** and verify normal SSO and `/auth/local` in separate private sessions.
8. Enable JIT, email matching, role synchronisation, preferred mode or required mode only when each is deliberately needed.

## Common problems

- A redirect error normally means authentik does not contain Kaya's exact callback URL.
- An issuer error means the configured issuer and discovery document do not identify the same provider.
- Missing groups require an authentik scope/property mapping and the same claim path in Kaya.
- A private certificate authority should be installed in Kaya's container trust store. Disabling verification should be a temporary, explicitly acknowledged fallback.
- If authentik is unavailable while Kaya is in required mode, use `/auth/local` with the designated break-glass administrator.

authentik is a primary compatibility target, but Kaya's core flow uses only standard discovery, Authorization Code with PKCE, ID tokens, JWKS, UserInfo and optional RP-initiated logout.
