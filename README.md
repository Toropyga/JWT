# JWT
A lightweight PHP class for creating, verifying, and managing JSON Web Tokens (JWT), including optional storage in browser cookies.

![License](https://img.shields.io/badge/license-MIT-brightgreen.svg)
![Version](https://img.shields.io/badge/version-v2.1.0-blue.svg)
![PHP](https://img.shields.io/badge/php-v7_--_v8-blueviolet.svg)

- **Namespace:** `Toropyga`
- **Class:** `JWT`
- **Version:** 2.1.1
- **Dependencies:** `Toropyga\Base` (used for array/object conversion helpers and `getKeyHash()`)
- **PHP:** 7.x / 8.x

> This README documents the hardened version of the class: unsigned tokens are rejected, the signing algorithm is validated against a whitelist, and sensitive data (tokens, payloads) is never written to logs, even in debug mode.

---

## Content

- [Features](#Features)
- [Installation](#Installation)
- [Quick start](#Quick-start)
- [Constructor](#Constructor)
- [Public API](#Public-API)
  - [`createJWT()`](#createjwtarray-header-array-user_data-string-security-stringfalse)
  - [`decodeJWT()`](#decodejwtstring-jwt-string-security-int-timestamp-null-int-leeway-0-object)
  - [`checkJWT()`](#checkjwtstring-jwt-string-security-int-timestamp-null-int-leeway-0-object)
  - [`getJWTData()`](#getjwtdatastring-jwt-array)
  - [`setJWT()`](#setjwtarrayobject-data-string-key-array-header-string-cookie_name-bool-hash-false-stringfalse)
  - [`clearJWT()`](#clearjwtstring-cookie_name-token-bool)
  - [`getLogs()`](#getlogs-array)
- [Static helper methods](#Static-helper-methods)
- [Supported algorithms](#Supported-algorithms)
- [Security considerations](#Security-considerations)
- [Error handling reference](#Error-handling-reference)

---

## Features

- Create and verify JWTs signed with HMAC (`HS256`, `HS384`, `HS512`).
- Strict algorithm whitelist — the `alg` from the token header must match one of the supported algorithms, preventing algorithm-confusion attacks.
- No unsigned tokens — both token creation and verification require a non-empty secret key.
- Standard claim validation on decode: `nbf`, `iat`, `exp`.
- Helpers to store/read/clear the JWT in an HTTP-only, SameSite cookie.
- `getJWTData()` to inspect a token's header/payload without verifying its signature (e.g. for logging or identifying the client behind a rejected/compromised token).
- Internal debug logging (`getLogs()`), with raw tokens and payload contents deliberately excluded from log output.

---

## Installation

Place the class under your `Toropyga` namespace (e.g. via Composer PSR-4 autoloading) together with the `Toropyga\Base` helper class it depends on.

```json
{
    "autoload": {
        "psr-4": {
            "Toropyga\\": "src/"
        }
    }
}
```

---

## Quick start

```php
use Toropyga\JWT;

$jwt = new JWT();

$secret = 'a-long-random-secret-key'; // store this in your app config / env, never hardcode in real projects

// 1. Create a token
$header = ['alg' => 'HS256', 'typ' => 'JWT'];
$payload = [
    'iss'       => 'https://example.com',
    'sub'       => 'user-123',
    'exp'       => time() + 3600,
    'user_id'   => 123,
    'user_name' => 'John Doe',
];

$token = $jwt->createJWT($header, $payload, $secret);
// $token === false on validation failure (see "Error handling" below)

header('Authorization: Bearer ' . $token);

// 2. Verify and decode a token
$data = $jwt->decodeJWT($token, $secret);

if (isset($data->error) && $data->error) {
    // invalid / expired / tampered token
    echo $data->info; // human-readable reason
} else {
    echo $data->user_name; // "John Doe"
}
```

---

## Constructor

```php
public function __construct($server_name = '')
```

| Parameter | Type | Description |
|---|---|---|
| `$server_name` | `string` | Optional. Server name used for cookie domain resolution. If omitted, falls back to `$_SERVER['SERVER_NAME']`. **Recommended:** always pass this explicitly from your application configuration rather than relying on the `Host` header, which can be influenced by the client in misconfigured server setups. |

The constructor also starts a PHP session (`session_start()`) if one isn't already active, since some helper methods (e.g. "remember me" duration) rely on `$_SESSION`.

```php
$jwt = new JWT('example.com');
```

---

## Public API

### `createJWT(array $header, array $user_data, string $security): string|false`

Builds and signs a JWT.

| Parameter | Description |
|---|---|
| `$header` | Must contain `alg` (one of `HS256`, `HS384`, `HS512`). Optional: `typ`, `cty`. |
| `$user_data` | Claims / payload. Optional standard claims: `iss`, `sub`, `aud`, `exp`, `nbf`, `jti`, plus any custom fields. |
| `$security` | Secret key used for HMAC signing. **Required** — must be a non-empty string. |

Returns the signed JWT string, or `false` if:
- a required header key is missing,
- the payload is empty,
- `alg` is not in the allowed list,
- `$security` is empty.

Check `getLogs()` for the specific reason when `false` is returned.

```php
$token = $jwt->createJWT(
    ['alg' => 'HS256', 'typ' => 'JWT'],
    ['iss' => 'https://example.com', 'exp' => time() + 3600, 'jti' => 1, 'user_id' => 1],
    'security_key_99'
);
```

---

### `decodeJWT(string $jwt, string $security, ?int $timestamp = null, int $leeway = 0): object`

Verifies a JWT's structure, signature, and standard time-based claims, then returns its payload.

| Parameter | Description |
|---|---|
| `$jwt` | The JWT string. |
| `$security` | Secret key used to verify the HMAC signature. **Required**. |
| `$timestamp` | Optional fixed "current time" for the check (Unix timestamp). Defaults to `time()`. |
| `$leeway` | Optional number of seconds of clock-skew tolerance for `nbf`/`iat`/`exp` checks. |

**Return value:**
- On success: a `stdClass` object with the token's claims (e.g. `$data->user_id`).
- On failure: a `stdClass` object shaped like:
  ```php
  {
      error: true,
      info: "human-readable reason",
      case: "segments|header|payload|signature|alg|security|signature check|nbf|iat|exp"
  }
  ```

Always check `$data->error` before trusting the returned object:

```php
$data = $jwt->decodeJWT($token, $secret);
if (!empty($data->error)) {
    // reject the request — see $data->info / $data->case for the reason
}
```

**Security notes:**
- The `alg` value from the token header is validated against an internal whitelist (`HS256`, `HS384`, `HS512`) before it is used to select the hashing algorithm — a token cannot force the server into an unexpected or unsafe algorithm.
- An empty `$security` key is rejected outright; signatures are never checked against an empty secret.

---

### `checkJWT(string $jwt, string $security = '', ?int $timestamp = null, int $leeway = 0): object`

Thin wrapper around `decodeJWT()`. Intended as the extension point for automatic token refresh logic (e.g. re-issuing a token that is close to expiry) — this logic is currently present only as a commented-out placeholder in the source and is **not implemented**. As it stands, `checkJWT()` behaves identically to `decodeJWT()`.

---

### `getJWTData(string $jwt): array`

Extracts the header and payload of a JWT **without verifying the signature**. Use this only for diagnostics — e.g. identifying the subject of a token that failed verification — never as a substitute for `decodeJWT()` when making authorization decisions.

Returns:
```php
[
    'header'  => [...],  // present only if the header decoded successfully and has a non-empty "alg"
    'payload' => [...],  // present only if the payload decoded successfully
]
```
Returns an empty array if the token is malformed.

> ⚠️ **Never use the output of `getJWTData()` to authenticate a user or authorize an action.** The signature is not checked, so the contents can be forged.

---

### `setJWT(array|object $data, string $key, array $header = [], string $cookie_name = '', bool $hash = false): string|false`

Creates a JWT via `createJWT()` and stores it in an HTTP-only cookie.

| Parameter | Description |
|---|---|
| `$data` | Payload (array or object, converted to array internally). |
| `$key` | Secret key. **Required** — must be a non-empty string. |
| `$header` | Optional; defaults to `['alg' => 'HS256', 'typ' => 'JWT']`. |
| `$cookie_name` | Optional; defaults to the internal `token_cookie_name` (`'token'`). |
| `$hash` | If `true`, stores an MD5 hash of the token (via `Base::getKeyHash()`) in the cookie instead of the raw token. |

If `$data['exp']` is not set, expiry is computed automatically:
- `session_live_time` (default 3600s) for a normal session, or
- `session_live_time_rem` (default 2,592,000s / 30 days) if `$_SESSION['remember']` is truthy.

Cookie flags used: `secure = true`, `httponly = true`, `samesite = 'lax'` (all configurable only by editing the class properties directly — no public setters currently exist).

Returns the generated JWT string, or `false` if `$data` is invalid, `$key` is empty, or token creation fails.

```php
$jwt->setJWT(['user_id' => 1, 'user_name' => 'John'], $secret);
```

---

### `clearJWT(string $cookie_name = 'token'): bool`

Expires the token cookie (and a few legacy-named cookies: `refresh_token`, `API`, `API_R`, kept for backward compatibility with older integrations). Returns `true` if a cookie was found and cleared, `false` otherwise.

```php
$jwt->clearJWT();
```

---

### `getLogs(): array`

Returns internal debug logs collected during the last operations, along with the configured log file name.

```php
[
    'log'  => [...],   // array of log lines (empty unless the internal $debug flag is enabled)
    'file' => 'jwt.log',
]
```

> Log entries deliberately omit raw tokens and decoded payload/header contents to avoid leaking sensitive user data — they report high-level status only (e.g. "token generated, length=123").

---

## Static helper methods

These are stateless and can be called without an instance:

| Method | Description |
|---|---|
| `JWT::jsonEncode($input)` | JSON-encodes an array (`JSON_FORCE_OBJECT \| JSON_NUMERIC_CHECK \| JSON_UNESCAPED_UNICODE`). |
| `JWT::jsonDecode($input, $assoc = false)` | JSON-decodes a string, preserving big integers as strings. |
| `JWT::base64Encode($input)` | Base64-URL encodes a string (no padding). |
| `JWT::base64Decode($input)` | Base64-URL decodes a string. Returns `false` on invalid input — always check the result before further use. |
| `JWT::getSignature($input, $key, $alg = 'sha256')` | Computes the base64-URL-encoded HMAC signature for `$input` using `$key` and the given hash algorithm. |

---

## Supported algorithms

| `alg` header value | Hash algorithm used |
|---|---|
| `HS256` | `sha256` |
| `HS384` | `sha384` |
| `HS512` | `sha512` |

Any other value in the token's `alg` header — including `none` — is rejected during both creation and verification.

---

## Security considerations

- **Never share the secret key** used for signing between untrusted parties; anyone with the key can mint valid tokens.
- **Always check `$data->error`** after calling `decodeJWT()` — a returned object is not proof of validity.
- **Set the cookie domain explicitly** via the constructor's `$server_name` parameter in production, rather than relying on the default `$_SERVER['SERVER_NAME']` fallback.
- **`getJWTData()` is not an authentication mechanism** — it does not check the signature.
- This class does not validate `iss`/`aud`/`sub` against expected values on decode; if your application relies on these claims for authorization, verify them explicitly after calling `decodeJWT()`.
- The automatic token-refresh logic referenced in `checkJWT()`'s docblock is not implemented (commented out in source) — implement it externally if needed, or extend the class.

---

## Error handling reference

`decodeJWT()` returns an object with `case` set to one of:

| `case` | Meaning |
|---|---|
| `first check` | `$jwt` was passed as an array instead of a string. |
| `segments` | Token does not have exactly 3 dot-separated segments. |
| `header` | Header segment is not valid Base64URL/JSON. |
| `payload` | Payload segment is not valid Base64URL/JSON. |
| `signature` | Signature segment is not valid Base64URL. |
| `alg` | `alg` is missing or not in the allowed algorithm list. |
| `security` | No secret key was provided for verification. |
| `signature check` | Signature does not match (token was tampered with or the key is wrong). |
| `nbf` | Token used before its "not before" time. |
| `iat` | Token's issued-at time is in the future. |
| `exp` | Token has expired. |

---

