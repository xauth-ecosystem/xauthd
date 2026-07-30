[![Stand With Ukraine](https://raw.githubusercontent.com/vshymanskyy/StandWithUkraine/main/banner-direct.svg)](https://stand-with-ukraine.pp.ua)

# XAuth Daemon (`xauthd`)

[![Rust CI](https://github.com/xauth-ecosystem/xauthd/actions/workflows/rust.yml/badge.svg)](https://github.com/xauth-ecosystem/xauthd/actions/workflows/rust.yml)
[![Test Coverage](https://img.shields.io/codecov/c/github/xauth-ecosystem/xauthd?label=Test%20Coverage&logo=codecov)](https://app.codecov.io/gh/xauth-ecosystem/xauthd)
[![License: CSSM Unlimited License v2.0](https://img.shields.io/badge/License-CSSM%20Unlimited%20License%20v2.0-blue.svg?logo=opensourceinitiative)](LICENSE)

A centralized authentication microservice for PocketMine-MP servers, written in Rust. `xauthd` uses gRPC for fast and secure communication with game servers, and JWT for stateless auth flow tracking.

## Core Features

- **Centralized Security:** Passwords and hashes (Argon2id/Bcrypt) are securely stored and verified exclusively within the daemon's core.
- **Dynamic Auth Flows (State Machine):** Configure the sequence of login steps (e.g., `captcha -> password -> totp`) in `xauthd.toml` without recompiling the core.
- **Stateless Flow Tracking:** The player's progress is securely passed using JWT tokens (`flow_token`), allowing `xauthd` to easily run in a multi-instance setup without bloating the database with dead sessions.
- **Built-in OAuth2 Provider:** Generates Access and Refresh tokens for secure authentication across web dashboards and other integrations.
- **gRPC API:** Lightning-fast messaging with PocketMine-MP instances via `xauth.proto`.

## Installation & Usage

### 1. Configuration

Create a configuration file from the template:
```bash
cp xauthd.example.toml xauthd.toml
```

Configure your database connection, password hashing algorithm, and `[auth_flow]` chains.

### 2. Running

To compile and run the development build:
```bash
cargo run -- start
```

To build the optimized release version for production:
```bash
cargo build --release
```

## CLI Commands

`xauthd` is a full-fledged CLI application. You can use the `--help` flag at any time to see the available commands:

```text
Usage: xauth-core <COMMAND>

Commands:
  start         Starts the XAuth Core Daemon (gRPC and Web servers)
  migrate       Manually applies database migrations
  config-check  Checks the xauthd.toml configuration for errors
  admin         Administrative commands
  help          Print this message or the help of the given subcommand(s)

Options:
  -h, --help     Print help
  -V, --version  Print version
```

Administrative commands are grouped under the `admin` subcommand:

```text
Usage: xauth-core admin <COMMAND>

Commands:
  reset-password       Resets a player's password
  unban                Unbans a player
  create-oauth-client  Creates a new OAuth2 Client
  help                 Print this message or the help of the given subcommand(s)
```

#### `reset-password`

Resets a player's password directly from the CLI.

```bash
xauth-core admin reset-password <USERNAME> <NEW_PASSWORD>
```

#### `unban`

Unbans a player by username.

```bash
xauth-core admin unban <USERNAME>
```

#### `create-oauth-client`

Registers a new OAuth2 client in the database.

```bash
xauth-core admin create-oauth-client --name <NAME> --redirect-uri <URI>
```

### Daemon Mode (Background)

By default, `start` runs the server in the foreground. If you are not using `systemd` and want the process to detach and run in the background as a classic daemon, pass the `-d` or `--daemon` flag:
```bash
./xauth-core start -d
```
Logs will be written to `xauthd.out` and `xauthd.err` in the current directory.

## Deployment

`xauthd` is designed to run continuously in the background on your server. You can deploy it using either Systemd (recommended for bare-metal/VPS) or Docker.

### Option A: Systemd

1. Compile the release build: `cargo build --release`
2. Move the binary and config to a safe location (e.g., `/opt/xauthd/`).
3. Copy the provided `xauthd.service` template to `/etc/systemd/system/xauthd.service`.
4. Edit the paths in the service file to match your setup.
5. Enable and start the service:
   ```bash
   systemctl daemon-reload
   systemctl enable --now xauthd
   ```
6. View logs with: `journalctl -u xauthd -f`

### Option B: Docker Compose

We provide a `Dockerfile` and a `docker-compose.yml` for containerized environments.

1. Ensure you have Docker and Docker Compose installed.
2. Create your `xauthd.toml` configuration file.
3. Start the daemon in the background:
   ```bash
   docker-compose up -d
   ```
4. View logs with: `docker-compose logs -f`

## Authentication Chains (Auth Flow)

In `xauthd.toml`, you can flexibly define the sequence of steps for players:
```toml
[auth_flow]
register_chain = ["captcha", "register"]
login_chain = ["password", "totp"]
```

The `xauthd` core natively handles security-critical steps (`password`, `register`, `totp`). Any custom steps, such as `captcha` or `send_gift`, are automatically delegated to your PocketMine plugin. The plugin must execute the step on the client side and return a `{step_name}_complete` gRPC signal to allow the player to proceed.

## Web Server & Templates

`xauthd` ships with a built-in HTTP server (Axum) that handles the OAuth 2.0 / OIDC web flow: login, consent, token exchange, JWKS, and discovery.

### Configuration

```toml
[network]
web_address = "0.0.0.0:8080"

[web]
templates_dir = "./templates"
public_dir = "./public"
```

| Key | Description |
|-----|-------------|
| `templates_dir` | Path to the directory containing HTML templates (MiniJinja syntax). |
| `public_dir` | Path to the directory for static assets (CSS, JS, images). Files are served under the `/static/` URL prefix. Leave empty to disable. |

The daemon will **panic on startup** if `templates_dir` does not exist. Create it before running:
```bash
mkdir -p templates public
```

### Customizing Templates

Templates are plain HTML files with [MiniJinja](https://docs.rs/minijinja) placeholders (Jinja2 syntax). The daemon reads them on every request — **no restart required** after edits.

Two templates are required:

| File | Purpose |
|------|---------|
| `templates/login.html` | Login form rendered by `GET /authorize` |
| `templates/consent.html` | OAuth consent page rendered by `GET /consent` |

#### `login.html` Variables

| Variable | Type | Description |
|----------|------|-------------|
| `{{ client_id }}` | string | The requesting application's ID. |
| `{{ redirect_uri }}` | string | Callback URL after auth. |
| `{{ state }}` | string | CSRF / state parameter. |
| `{{ code_challenge }}` | string | PKCE code challenge. |
| `{{ code_challenge_method }}` | string | `S256` or `plain`. |
| `{{ nonce }}` | string | OIDC nonce. |
| `{{ error }}` | string \| none | Error message from a failed login attempt. |

#### `consent.html` Variables

| Variable | Type | Description |
|----------|------|-------------|
| `{{ client_id }}` | string | The requesting application's ID. |
| `{{ redirect_uri }}` | string | Callback URL after consent. |
| `{{ state }}` | string | CSRF / state parameter. |
| `{{ username }}` | string | Authenticated player's username. |
| `{{ scopes_list }}` | string | Space-separated list of requested scopes. |
| `{{ code_challenge }}` | string | PKCE code challenge. |
| `{{ code_challenge_method }}` | string | `S256` or `plain`. |
| `{{ nonce }}` | string | OIDC nonce. |

### Static Assets

Place CSS, JS, images, or fonts in the `public_dir` directory. They are served under `/static/`:

```
public/
+-- styles.css
\-- logo.png
```

Reference them in your templates:
```html
<link rel="stylesheet" href="/static/styles.css">
<img src="/static/logo.png" alt="Logo">
```

If `public_dir` is not set or the directory does not exist, static file serving is silently disabled.

### API Endpoints

#### `GET /.well-known/openid-configuration`

Returns the OIDC discovery document.

```json
{
  "issuer": "http://localhost:8080",
  "authorization_endpoint": "http://localhost:8080/authorize",
  "token_endpoint": "http://localhost:8080/token",
  "jwks_uri": "http://localhost:8080/jwks",
  "scopes_supported": ["openid", "profile"],
  "response_types_supported": ["code"],
  "grant_types_supported": ["authorization_code", "refresh_token"],
  "id_token_signing_alg_values_supported": ["RS256"]
}
```

#### `GET /jwks`

Returns the RSA public keys in JWKS format.

```json
{
  "keys": [
    {
      "kty": "RSA",
      "alg": "RS256",
      "use": "sig",
      "kid": "default",
      "n": "...",
      "e": "..."
    }
  ]
}
```

#### `GET /authorize`

Renders the `login.html` template.

- **Query Parameters:**
  - `client_id` (required): The ID of the registered client.
  - `redirect_uri` (required): The callback URL where the user will be sent after login.
  - `state` (optional): An opaque CSRF parameter.
  - `code_challenge` (required): A PKCE code challenge.
  - `code_challenge_method` (required): `S256` or `plain`.
  - `nonce` (optional): An OIDC nonce.
  - `error` (optional): An error message from a previous attempt to display in the template.

#### `POST /login`

Handles the login form submission.

- **Form Parameters:**
  - `username` (required): The player's username.
  - `password` (required): The player's password.
  - `client_id`, `redirect_uri`, `state`, `code_challenge`, `code_challenge_method`, `nonce` — passed through from the authorize step.
- **On Success:** Returns a JSON response with a `redirect_url` pointing to the consent page.
  ```json
  {
    "redirect_url": "/consent?client_id=...&redirect_uri=...&state=...",
    "error": null
  }
  ```
- **On Failure:** Returns a JSON response with an `error` message.
  ```json
  {
    "redirect_url": null,
    "error": "Invalid username or password"
  }
  ```

#### `GET /consent`

Renders the `consent.html` template. Reads the authenticated player's username from the session cookie.

- **Query Parameters:**
  - `client_id`, `redirect_uri`, `state`, `code_challenge`, `code_challenge_method`, `nonce` — passed through from the login step.

#### `POST /consent`

Approves or denies the scope access request.

- **Form Parameters:**
  - `action` (required): `approve` or `deny`.
  - `client_id`, `redirect_uri`, `state`, `code_challenge`, `code_challenge_method`, `nonce` — passed through from the previous step.
- **On Approve:** Redirects the user to `redirect_uri?code=<jwt>&state=...`.
- **On Deny:** Redirects the user to `redirect_uri?error=access_denied&state=...`.

#### `POST /token`

Handles the OAuth2 token endpoint. Supports two grant types: `authorization_code` (exchange code for tokens) and `refresh_token` (exchange refresh token for new tokens). This should be a server-to-server request.

##### `grant_type=authorization_code`

Exchanges an authorization code for access and refresh tokens.

- **Form Parameters:**
  - `grant_type` (required): `authorization_code`.
  - `code` (required): The authorization code received from the consent step.
  - `redirect_uri` (required): The same redirect URI used during consent.
  - `client_id` (required): The client ID.
  - `client_secret` (required): The client secret.
  - `code_verifier` (required if `code_challenge` was provided): The PKCE code verifier.
- **On Success:** Returns a JSON object with the tokens.
  ```json
  {
    "access_token": "...",
    "token_type": "Bearer",
    "expires_in": 3600,
    "refresh_token": "...",
    "id_token": "..."
  }
  ```
- **On Failure:**
  - `invalid_client` (401): Invalid `client_id` or `client_secret`.
  - `invalid_grant` (400): Invalid or expired code, or PKCE verification failed.

##### `grant_type=refresh_token`

Exchanges a refresh token for a new access token and a new refresh token (rotation: the old refresh token is invalidated).

- **Form Parameters:**
  - `grant_type` (required): `refresh_token`.
  - `refresh_token` (required): The refresh token obtained previously.
  - `client_id` (required): The client ID.
  - `client_secret` (required): The client secret.
- **On Success:** Returns a JSON object with the new tokens.
  ```json
  {
    "access_token": "...",
    "token_type": "Bearer",
    "expires_in": 3600,
    "refresh_token": "...",
    "id_token": "..."
  }
  ```
- **On Failure:**
  - `invalid_client` (401): Invalid `client_id` or `client_secret`.
  - `invalid_request` (400): Missing `refresh_token` parameter.
  - `invalid_grant` (400): Refresh token is invalid, expired, revoked, or was issued to another client.

#### `GET /user`

Returns user information for a valid access token.

If the token contains custom data scopes (e.g., `economy:balance`, `guilds:name`) that `xauthd` does not store internally, the daemon performs **Dynamic Scope Resolution** via gRPC.

- **Dynamic Scope Resolution:** `xauthd` pauses the HTTP request and broadcasts a `FETCH_SCOPES` command to connected game servers. The game server resolves the requested scopes from memory and pushes the data back via `SCOPE_DATA_RESPONSE`. This data is then merged into the final JSON payload. (Timeout: 3 seconds).
- **Headers:**
  - `Authorization: Bearer <access_token>`
- **On Success:** Returns a JSON object with the user info and any dynamically resolved scopes.
  ```json
  {
    "sub": "player1",
    "preferred_username": "player1",
    "name": "player1",
    "economy:balance": 1500.50,
    "guilds:name": "Warriors"
  }
  ```
- **On Failure:**
  - `invalid_token` (401): The token is missing, expired, or blacklisted.

#### `POST /introspect`

Checks whether a token is active and returns its metadata.

- **Form Parameters:**
  - `token` (required): The access or refresh token to introspect.
  - `client_id` (required): The client ID.
  - `client_secret` (required): The client secret.
- **On Success (active):**
  ```json
  {
    "active": true,
    "sub": "player1",
    "username": "player1",
    "exp": 1678886400,
    "iat": 1678882800,
    "scope": "openid profile",
    "client_id": "my_client"
  }
  ```
- **On Success (inactive):**
  ```json
  { "active": false }
  ```
- **On Failure:**
  - `invalid_client` (401): Invalid `client_id` or `client_secret`.

#### `POST /revoke`

Revokes an access or refresh token.

- **Form Parameters:**
  - `token` (required): The access or refresh token to revoke.
  - `client_id` (required): The client ID.
  - `client_secret` (required): The client secret.
- **On Success:** Returns an empty 200 OK response.
- **On Failure:**
  - `invalid_client` (401): Invalid `client_id` or `client_secret`.

## Client Libraries

To connect your PocketMine-MP (PHP) or Nukkit/Spigot/Paper (Java) plugin to `xauthd`, generate gRPC client stubs from `proto/xauth.proto`. See [docs/code-generation.md](docs/code-generation.md) for setup instructions.

For a detailed specification of the bidirectional `ConnectServer` stream, supported events, and expected JSON payloads, refer to the [gRPC Protocol Specification](docs/grpc-protocol.md).

## Contributing

Contributions are welcome and appreciated! Here's how you can contribute:

1. Fork the project
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

Please make sure to update tests as appropriate and adhere to the existing coding style.

## License

This project is licensed under the CSSM Unlimited License v2.0 (CSSM-ULv2). Please note that this is a custom license. See the [LICENSE](LICENSE) file for details.
