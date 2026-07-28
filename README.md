# XAuth Daemon (`xauthd`)

[![Rust CI](https://github.com/xauth-ecosystem/xauthd/actions/workflows/rust.yml/badge.svg)](https://github.com/xauth-ecosystem/xauthd/actions/workflows/rust.yml)
[![Test Coverage](https://img.shields.io/codecov/c/github/xauth-ecosystem/xauthd?label=Test%20Coverage&logo=codecov)](https://app.codecov.io/gh/xauth-ecosystem/xauthd)

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

Administrative commands are grouped under the `admin` subcommand (e.g., `xauth-core admin --help`).

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

## Contributing

Contributions are welcome and appreciated! Here's how you can contribute:

1. Fork the project on GitHub.
2. Create your feature branch (`git checkout -b feature/AmazingFeature`).
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`).
4. Push to the branch (`git push origin feature/AmazingFeature`).
5. Open a Pull Request.

Please make sure to update tests as appropriate and adhere to the existing coding style.

## License

This project is licensed under the CSSM Unlimited License v2.0 (CSSM-ULv2). Please note that this is a custom license. See the [LICENSE](LICENSE) file for details.
