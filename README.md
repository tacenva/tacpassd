# tacpassd

Tacenva Password Manager daemon.

`tacpassd` is the server-side daemon for the Tacenva Password Manager ecosystem. It provides secure remote access to password vaults and enables online functionality for clients such as [`tacpass-tui`](https://github.com/tacenva/tacpass-tui).

`tacpassd` is optional. Local password management with `tacpass-tui` does not require a running daemon.

## Download

Pre-built binaries are available in the GitHub Releases.

**[Download the latest release](https://github.com/tacenva/tacpassd/releases/latest)**

Choose the binary matching your operating system and architecture.

## Features

* HTTPS API
* Remote password vault access
* Vault management
* Password record management
* User authentication
* User enrollment
* Access control
* Permission management
* Vault synchronization
* TLS support
* Local encrypted storage

## Architecture

`tacpassd` uses [`tacpass-core`](https://github.com/tacenva/tacpass-core) for its core application services and [`database`](https://github.com/tacenva/database) for encrypted data storage.

```text
                  Online
                    │
                    │ HTTPS
                    ▼
             ┌───────────────┐
             │   tacpassd    │
             │    Daemon     │
             └───────┬───────┘
                     │
                     ▼
             ┌───────────────┐
             │  tacpass-core │
             │ Core Services │
             └───────┬───────┘
                     │
                     ▼
             ┌───────────────┐
             │    database   │
             │ Encrypted DB  │
             └───────────────┘
```

Clients such as `tacpass-tui` can connect to `tacpassd` when online functionality is required.

```text
┌─────────────────┐
│   tacpass-tui   │
│  Terminal App   │
└────────┬────────┘
         │
         │ HTTPS
         ▼
┌─────────────────┐
│    tacpassd     │
│     Daemon      │
└─────────────────┘
```

## Requirements

* Linux, macOS, or Windows
* A network interface accessible by clients

No separate server software or runtime is required.

## Configuration

`tacpassd` stores its configuration and application data under:

```text
~/.tacenva/
```

The main configuration file is:

```text
~/.tacenva/config.toml
```

The default HTTPS port is:

```text
9443
```

TLS certificate and private key paths are configured through the configuration file.

The daemon generates a self-signed certificate when required.

## Authentication

`tacpassd` provides authentication for clients connecting to the daemon.

The authentication flow supports:

* User enrollment
* User approval
* Login
* Bearer token authentication
* Permission-based access control

Protected API endpoints require a valid authentication token.

## Access Control

Administrators can manage:

* Permissions
* Permission privileges
* Users
* User approval
* User revocation

Vault operations are performed according to the authenticated user's permissions.

## Security

Communication between clients and `tacpassd` uses HTTPS.

Sensitive vault data is stored using the encrypted database layer provided by [`database`](https://github.com/tacenva/database).

`tacpassd` should only be exposed to trusted networks or protected by appropriate network security controls.

## Ecosystem

* [`tacpass-tui`](https://github.com/tacenva/tacpass-tui) - Standalone terminal application
* [`tacpassd`](https://github.com/tacenva/tacpassd) - Daemon for online functionality
* [`tacpass-core`](https://github.com/tacenva/tacpass-core) - Core functionality
* [`database`](https://github.com/tacenva/database) - Encrypted database layer

## License

This project is free to use.

See the repository license for details.
