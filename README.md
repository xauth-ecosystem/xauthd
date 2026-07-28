# XAuth Daemon (`xauthd`)

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
cargo run
```
To build the optimized release version for production:
```bash
cargo build --release
```

## Authentication Chains (Auth Flow)
In `xauthd.toml`, you can flexibly define the sequence of steps for players:
```toml
[auth_flow]
register_chain = ["captcha", "register"]
login_chain = ["password", "totp"]
```
The `xauthd` core natively handles security-critical steps (`password`, `register`, `totp`). Any custom steps, such as `captcha` or `send-gift`, are automatically delegated to your PocketMine plugin. The plugin must execute the step on the client side and return a `{step_name}_complete` gRPC signal to allow the player to proceed.
