# Configure authentik as Kaya's identity provider

This guide explains how to connect Kaya to authentik using OpenID Connect (OIDC). It is written for administrators who are comfortable using the authentik and Kaya web interfaces but do not need to know the OIDC protocol in detail.

When the integration is complete, people can authenticate with authentik and use their existing Kaya account. Kaya continues to control whether an account is active, which Kaya role it has, and which modules it can access.

> **Do not enable OIDC-required mode at the beginning.** Keep local login available until configuration, account linking, normal login, logout, and emergency access have all been tested.

## What you will configure

The setup has four parts:

1. Prepare Kaya and preserve an emergency local administrator.
2. Create an OAuth2/OpenID provider and application in authentik.
3. Configure claims, including authentik's verified-email behavior.
4. Test the provider and link existing Kaya accounts.

Kaya uses:

- OIDC Authorization Code flow
- PKCE with `S256`
- A confidential client ID and client secret
- OIDC discovery
- Asymmetrically signed ID tokens
- The standard `openid profile email` scopes
- Optional group-to-role mapping
- Optional provider logout

Kaya does not require an authentik API token and does not store refresh tokens.

## Example addresses

Replace these examples with your real addresses throughout the guide:

| Service | Example |
| --- | --- |
| Kaya | `https://kaya.example.com` |
| authentik | `https://auth.example.com` |
| Application slug | `kaya` |
| Kaya callback | `https://kaya.example.com/auth/oidc/callback` |
| authentik issuer | `https://auth.example.com/application/o/kaya/` |

Use HTTPS for both services. HTTP is supported only for localhost development.

## Before you start

You need:

- Administrator access to Kaya
- Administrator access to authentik
- Working DNS and HTTPS for Kaya and authentik
- Network access from the Kaya container to the authentik hostname
- At least one active local Kaya administrator with a working password

In Kaya:

1. Open **Site Administration > General**.
2. Confirm that Kaya's public base URL is correct.
3. Open **Site Administration > Authentication > General**.
4. Leave the authentication mode set to **Local only**.
5. Enable emergency local access.
6. Under **Users**, select one active local administrator as the emergency or break-glass administrator.
7. Test that account at `/auth/local` before continuing.

The break-glass account should use a strong password and Kaya 2FA. Do not make an OIDC-only account the break-glass account.

## Step 1: Create the authentik application and provider

authentik recommends creating an application and provider together.

1. Sign in to the authentik Admin interface.
2. Open **Applications > Applications**.
3. Select **New Application**, **New Provider**, or **Create with Provider**. The label varies between authentik releases.
4. Enter an application name such as `Kaya`.
5. Set the slug to `kaya`.
6. Choose **OAuth2/OIDC** as the provider type.

Configure the provider with these values:

| authentik setting | Recommended value |
| --- | --- |
| Name | `Kaya` |
| Client type | `Confidential` |
| Authorization flow | Your normal provider authorization flow |
| Redirect URI mode | `Strict` |
| Redirect URI | Copy the callback displayed by Kaya |
| Signing key | Select an RSA signing certificate |
| Encryption key | Leave empty |
| Issuer mode | Per-provider/default mode |
| Subject mode | Default hashed user ID |

### Redirect URI

Copy the exact callback URL from **Kaya > Site Administration > Authentication > OpenID Connect**. It normally looks like:

```text
https://kaya.example.com/auth/oidc/callback
```

The scheme, hostname, port, path, and trailing slash must match exactly. Use a strict URI rather than a wildcard or regular expression.

### Signing key

The **Signing key** must not be empty. Select an RSA certificate, commonly the authentik self-signed certificate, or another certificate managed by your authentik installation.

When no signing key is selected, authentik signs tokens symmetrically with the client secret. Kaya intentionally rejects symmetric ID-token algorithms. With a signing key selected, authentik publishes the public key through its JWKS endpoint and Kaya can verify the token without possessing authentik's private key.

Leave **Encryption key** empty. Kaya validates signed ID tokens but does not consume encrypted ID tokens or JWEs.

### Client credentials

Finish creating the provider, then copy:

- **Client ID**
- **Client secret**

The client ID is not the application name, provider name, or slug. Copy the exact value shown on the authentik provider.

Treat the client secret like a password. Kaya encrypts it when saved and does not display it again.

## Step 2: Confirm the issuer and discovery document

With authentik's recommended per-provider issuer mode, the issuer normally has this form:

```text
https://auth.example.com/application/o/kaya/
```

Keep the trailing slash if authentik advertises it.

The discovery document is normally:

```text
https://auth.example.com/application/o/kaya/.well-known/openid-configuration
```

Open that address in a browser. It should return JSON containing values such as:

```json
{
  "issuer": "https://auth.example.com/application/o/kaya/",
  "authorization_endpoint": "https://auth.example.com/application/o/authorize/",
  "token_endpoint": "https://auth.example.com/application/o/token/",
  "jwks_uri": "https://auth.example.com/application/o/kaya/jwks/"
}
```

Use the exact `issuer` value from this document in Kaya. Do not enter the authorization endpoint, token endpoint, or discovery-document address as the issuer.

After selecting the signing key, the discovery document should advertise an asymmetric algorithm such as `RS256`, and the `jwks_uri` should return at least one public key.

## Step 3: Configure scopes and verified email

Kaya requests:

```text
openid profile email
```

In the authentik provider, retain the standard OpenID/profile mappings. The profile mapping normally supplies username, name, and group membership. The email mapping supplies the user's email address.

### Important change in authentik 2025.10 and later

Current authentik releases return `email_verified: false` by default because authentik cannot assume every stored email address has been independently verified. Kaya requires a verified email by default, so you must deliberately configure how authentik determines verification.

The recommended approach is to store verification status on each authentik user.

1. Open **Customization > Property Mappings** in authentik.
2. Select **Create**.
3. Choose **OAuth2/OpenID Scope Mapping**.
4. Configure:

   | Setting | Value |
   | --- | --- |
   | Name | `Kaya verified email` |
   | Scope name | `email` |
   | Description | `Verified email claims for Kaya` |

5. Use this expression:

   ```python
   return {
       "email": request.user.email,
       "email_verified": request.user.attributes.get("email_verified", False),
   }
   ```

6. Open **Directory > Users** and edit each approved user.
7. Add this user attribute only after verifying the address:

   ```yaml
   email_verified: true
   ```

8. Return to **Applications > Providers > Kaya**.
9. Remove the default email scope mapping from this provider.
10. Add **Kaya verified email**.
11. Keep the standard OpenID and profile mappings.
12. Save the provider.

### Simpler mapping for administrator-managed directories

If accounts and email addresses are created and verified exclusively by trusted administrators, the mapping can always assert verification:

```python
return {
    "email": request.user.email,
    "email_verified": True,
}
```

Do not use this version with untrusted imports or self-service enrollment unless that process actually verifies email ownership.

Disabling **Require verified email** in Kaya is available for diagnosis, but is not the recommended permanent solution.

## Step 4: Optional groups and Kaya roles

If authentik will control initial Kaya roles, create authentik groups such as:

```text
Kaya Admins
Kaya Editors
Kaya Users
```

Add users to the appropriate groups. authentik's standard profile mapping normally returns group membership in the `groups` claim.

In Kaya, use exact mappings such as:

```text
Kaya Admins=admin
Kaya Editors=editor
Kaya Users=viewer
```

Kaya applies the highest matching role in this order:

```text
admin > editor > viewer
```

Keep the default role as `viewer`. Do not enable role synchronization until a test login shows the expected groups and resolved role. Kaya prevents an OIDC mapping from demoting the last active administrator.

If groups do not appear, create an additional OAuth2 scope mapping in authentik with an expression such as:

```python
return {
    "groups": [group.name for group in request.user.groups.all()],
}
```

Use `request.user.groups` with current authentik releases. The older `ak_groups` property is deprecated.

## Step 5: Restrict access to the authentik application

Without bindings, an authentik application may be available to every authentik user.

To restrict access:

1. Open **Applications > Applications > Kaya**.
2. Open **Policy / Group / User Bindings**.
3. Bind the users, groups, or policies that are allowed to use Kaya.
4. Test with both an approved and an unapproved account.

This controls who may authenticate to the Kaya application. Kaya still applies its own account-active and role checks after authentication.

## Step 6: Configure Kaya

Open **Site Administration > Authentication > OpenID Connect** and enter:

| Kaya setting | Value |
| --- | --- |
| Provider name | `authentik` |
| Issuer | Exact issuer from the discovery document |
| Client ID | Exact client ID copied from authentik |
| Client secret | Exact client secret copied from authentik |
| Requested scopes | `openid profile email` |
| Enabled | Enable after entering the provider details |
| Verify TLS certificates | Enabled |
| Use UserInfo endpoint | Enabled |
| Require verified email | Enabled |
| Allow JIT provisioning | Disabled initially |
| Synchronize mapped role at login | Disabled initially |
| Update names at login | Optional |
| Update email at login | Disabled initially |
| End IdP session during logout | Optional |

Keep the default claim names:

| Kaya value | Claim |
| --- | --- |
| Email | `email` |
| Email verified | `email_verified` |
| Display name | `name` |
| First name | `given_name` |
| Last name | `family_name` |
| Preferred username | `preferred_username` |
| Groups | `groups` |

If **Allowed email domains** is used, enter exact domains only:

```text
example.com
```

This permits `person@example.com` but not `person@fakeexample.com`. Leave the field blank if domain restriction is not required.

Save the provider. Leaving the client-secret box blank on a later edit preserves the stored secret.

## Step 7: Test the configuration

Select **Test configuration** in Kaya.

A successful test confirms that Kaya can:

- Resolve the authentik hostname
- Download the discovery document
- Match the configured and discovered issuer
- Find the authorization and token endpoints
- Confirm Authorization Code and PKCE support
- Find a supported asymmetric signing algorithm
- Download authentik's public signing keys

Then select **Test OIDC login**. Authenticate with an approved authentik account and review Kaya's sanitized preview.

Confirm:

- The email is correct
- Email verification is `true`
- The subject is present
- First and last name are sensible
- Expected groups are present
- The proposed Kaya role is correct

The test login validates claims but does not link the identity to the currently signed-in Kaya account.

## Step 8: Link an existing Kaya account

Existing local users should explicitly link their identities.

1. Sign in to Kaya using the existing local email and password.
2. Open the avatar menu.
3. Select **Profile Settings**.
4. Under **Sign-in methods**, confirm that OpenID Connect says **Not linked**.
5. Select **Link OIDC account**.
6. Authenticate with authentik.
7. Review the identity shown by Kaya.
8. Select **Confirm account link**.

Use the same browser session for the complete process. Do not use the main SSO button or **Test OIDC login** to link an existing account.

After linking, the profile should show the provider name, OIDC email, and last OIDC login. The Audit Log should contain **OIDC Identity Linked**.

An administrator can alternatively create a single-use linking invitation from Kaya's authentication administration page. Invitations expire and should be delivered privately to the intended user.

## Step 9: Enable SSO safely

After linking the first administrator:

1. Change Kaya's mode to **Local and OIDC**.
2. Open a private browser window.
3. Select the SSO button and complete an authentik login.
4. Confirm the correct Kaya account and role are used.
5. Log out and confirm the expected logout behavior.
6. In a separate private window, test `/auth/local` with the break-glass administrator.
7. Repeat with a normal non-administrator account.

Only after these checks should you consider:

- OIDC preferred mode
- OIDC required mode
- JIT provisioning
- Automatic or confirmation-based email matching
- Role synchronization

Kaya blocks OIDC-required mode until provider configuration and a real test login have succeeded and a usable break-glass administrator exists.

## Optional JIT provisioning

Just-in-time provisioning creates a new Kaya account when a valid authentik identity has no existing link.

Before enabling it:

- Restrict access to the authentik application
- Configure verified email correctly
- Consider an exact allowed-domain list
- Keep the default Kaya role as `viewer`
- Test group mappings
- Acknowledge the JIT warning in Kaya

JIT users are OIDC-only by default. They do not have a local Kaya password and cannot use Kaya's local password reset or local TOTP flow.

## Optional logout integration

Enable **End IdP session during logout** in Kaya if a Kaya logout should call authentik's OIDC end-session endpoint.

Register the post-logout URL displayed by Kaya if required by the authentik provider. Kaya keeps the ID-token hint encrypted in its server-side session, uses it only for provider logout, and removes it when the Kaya session ends.

authentik normally ends the application session during RP-initiated logout while leaving sessions for other applications intact. Configure full single logout in authentik only if that broader behavior is intended.

## Troubleshooting

### Provider does not advertise a supported asymmetric signing algorithm

**Cause:** The authentik provider has no signing key and is using symmetric signing.

**Fix:** Edit **Applications > Providers > Kaya**, select an RSA **Signing key**, leave **Encryption key** empty, save, and rerun Kaya's configuration test.

### Authentik displays “Client ID Error”

**Cause:** The client ID sent by Kaya is empty, incorrect, or belongs to another provider.

**Fix:** Copy the exact **Client ID** from the authentik OAuth2/OpenID provider into Kaya. Do not use the application slug or provider name. Re-enter the client secret and save.

### Selecting “Link OIDC account” appears to do nothing

First confirm the server log contains:

```text
POST /profile/identity/link ... 302 Found
```

If it does, use a Kaya version that dynamically permits the configured provider origin in its Content Security Policy. Kaya does not hard-code authentik hostnames; it reads the validated authorization origin from OIDC discovery and adds only that origin to `form-action`.

After upgrading or restarting Kaya, perform a hard refresh with `Ctrl+F5`.

### Callback returns HTTP 400 after successful authentik login

The transport is working, but Kaya rejected an identity claim or account policy. Open Kaya's error page or inspect **Audit Logs** for **OIDC Link Failed** and its failure category.

Common causes are:

- `unverified_email`: configure the verified-email scope mapping described above
- `missing_or_invalid_email`: ensure the `email` scope mapping returns an address
- `disallowed_email_domain`: correct Kaya's allowed-domain list
- `identity_conflict`: the authentik identity is linked to another Kaya account
- `user_identity_conflict`: the Kaya user is linked to a different external identity

### Issuer mismatch

Use the exact `issuer` value from authentik's discovery document. Do not substitute the authentik home page, authorization endpoint, or discovery URL.

### Redirect URI error

Copy Kaya's displayed callback into authentik as a strict redirect URI. Check HTTPS, hostname, port, path, reverse-proxy configuration, and trailing slash.

### Missing groups

Confirm the authentik profile mapping is selected and Kaya requests `profile`. If necessary, add the custom groups mapping shown earlier. Run **Test OIDC login** before enabling role synchronization.

### Private certificate authority

Install the private CA certificate in the Kaya container's trust store. Temporarily disabling TLS verification can help diagnose a CA problem, but should not be the permanent configuration.

### authentik works in a browser but Kaya cannot connect

The Kaya container must resolve and reach the authentik hostname independently of the user's browser. Check container DNS, firewall rules, reverse proxy routing, and certificate trust.

### User is authenticated but not authorized

For an existing account, sign in locally and use **Profile Settings > Link OIDC account**. A normal SSO login does not automatically link by email unless an administrator deliberately enables email matching. For a new user, either create and link a local account or deliberately enable JIT provisioning.

## Audit events

Useful Kaya audit events include:

| Event | Meaning |
| --- | --- |
| OIDC Login Started | Kaya accepted a normal or test login initiation |
| OIDC Link Started | A signed-in user started explicit account linking |
| OIDC Test Login Succeeded | Token and claims were validated for testing |
| OIDC Identity Linked | An authentik identity was linked to a Kaya user |
| OIDC Link Failed | Linking failed; inspect the failure category |
| OIDC Login Succeeded | A linked user completed SSO |
| OIDC Logout Started | Kaya redirected to the provider logout endpoint |

Kaya redacts authorization codes and callback query values from its access logs. Client secrets, tokens, PKCE verifiers, and nonce values should never be copied into support tickets.

## Rollback and recovery

If SSO is unavailable:

1. Open `/auth/local`.
2. Sign in with the designated break-glass administrator.
3. Change the authentication mode to **Local only** or **Local and OIDC**.
4. Disable the provider if necessary.
5. Correct and retest the provider before restoring preferred or required mode.

Disabling the provider does not delete local users. Deleting a provider is blocked while linked identities still exist; unlink or migrate those users deliberately first.

## Official authentik references

- [Create an OAuth2/OIDC provider](https://docs.goauthentik.io/add-secure-apps/providers/oauth2/create-oauth2-provider)
- [OAuth2/OpenID provider behavior, endpoints, signing, scopes, and issuer modes](https://docs.goauthentik.io/add-secure-apps/providers/oauth2/)
- [Provider property mappings](https://docs.goauthentik.io/add-secure-apps/providers/property-mappings/)
- [Application access bindings](https://docs.goauthentik.io/add-secure-apps/applications/manage_apps/)

See also Kaya's [general OpenID Connect guide](openid-connect.md).
