# xauthd gRPC Protocol Specification

This document provides a detailed specification of the gRPC bidirectional stream (`ConnectServer`) used for real-time communication between the `xauthd` core and connected Minecraft server instances.

## Bi-Directional Stream: `ConnectServer`

The `ConnectServer` RPC method establishes a persistent, long-lived connection between the game server plugin and `xauthd`. 

```protobuf
rpc ConnectServer (stream PluginEvent) returns (stream CoreCommand);
```

- **Client (Game Server) -> Server (xauthd):** Sends `PluginEvent` messages to notify the core of state changes or respond to data requests.
- **Server (xauthd) -> Client (Game Server):** Pushes `CoreCommand` messages to instruct the game server to perform actions or fetch data.

---

## 1. Plugin Events (Game Server -> xauthd)

The game server must emit `PluginEvent` messages whenever a relevant state change occurs in the game, or to reply to specific core commands.

### Message Structure

```protobuf
message PluginEvent {
    string server_id = 1;
    EventType type = 2;
    string username = 3;
    string ip_address = 4;
    string payload = 5;
}
```

### Event Types

#### `SERVER_START` (0)
Emitted once immediately after the gRPC stream is successfully established. Used by `xauthd` to register the `server_id` and map it to the active connection channel.
- `username`: *(Empty)*
- `ip_address`: *(Empty)*
- `payload`: *(Empty)*

#### `SERVER_STOP` (1)
Emitted gracefully when the game server is shutting down.
- `username`: *(Empty)*
- `ip_address`: *(Empty)*
- `payload`: *(Empty)*

#### `PLAYER_JOIN` (2)
Emitted when a player connects to the game server.
- `username`: The player's exact username.
- `ip_address`: The player's connecting IP address.
- `payload`: *(Empty)*

#### `PLAYER_QUIT` (3)
Emitted when a player disconnects from the game server.
- `username`: The player's exact username.
- `ip_address`: *(Empty)*
- `payload`: *(Empty)*

#### `STATE_UPDATE` (4)
Reserved for future synchronization of custom player states or offline data.

#### `SCOPE_DATA_RESPONSE` (5)
Emitted as a direct response to a `FETCH_SCOPES` command from `xauthd`. Used during Dynamic Scope Resolution to provide custom player data (e.g., balance, guild) to the HTTP `/user` endpoint.
- `username`: The target player's username.
- `ip_address`: *(Empty)*
- `payload`: A JSON string containing the original `request_id` and the resolved `data` key-value pairs.
  ```json
  {
    "request_id": "Steve-123456789",
    "data": {
      "economy:balance": 1500.50,
      "guilds:name": "Warriors"
    }
  }
  ```

---

## 2. Core Commands (xauthd -> Game Server)

The `xauthd` daemon will asynchronously push `CoreCommand` messages down the stream to trigger actions on the game server. The game server plugin must constantly listen to the receive stream and execute these commands immediately.

### Message Structure

```protobuf
message CoreCommand {
    CommandType type = 1;
    string target_username = 2;
    string payload = 3;
}
```

### Command Types

#### `KICK_PLAYER` (0)
Instructs the game server to forcefully disconnect the target player.
- `target_username`: The player to kick.
- `payload`: The kick reason/message to display to the player (plain text).

#### `SEND_MESSAGE` (1)
Instructs the game server to send a chat message to the target player.
- `target_username`: The player to message.
- `payload`: The message content (plain text or game-formatted string).

#### `FORCE_STATE_SYNC` (2)
Reserved for requesting a forced update of player state data.

#### `REQUIRE_REAUTH` (3)
Instructs the game server to freeze the player's movement and force them to undergo the authentication flow again (e.g., triggered via an admin dashboard action).
- `target_username`: The player to freeze.
- `payload`: *(Empty or optional reason)*

#### `FETCH_SCOPES` (4)
Instructs the game server to gather custom data for specific OAuth2 scopes from its memory/providers and send it back via a `SCOPE_DATA_RESPONSE` event.
- `target_username`: The player whose data is being requested.
- `payload`: A JSON string containing a unique `request_id` and an array of requested `scopes`.
  ```json
  {
    "request_id": "Steve-123456789",
    "scopes": ["economy:balance", "guilds:name"]
  }
  ```
