# Vault

A secure, local CLI-based password manager built in Go. Store and manage your passwords with military-grade encryption, all stored locally on your machine.

## Features

- **🔐 Strong Encryption**: AES-256-GCM encryption with Argon2id key derivation
- **🔑 Master Password**: Single master password protects all your credentials
- **💾 Local Storage**: All data stored locally in `~/.vault.json`
- **📋 Clipboard Integration**: Automatic password copying to clipboard
- **🎯 Interactive Mode**: User-friendly command-line interface
- **🔒 Memory Safety**: Sensitive data zeroed out after use to prevent memory leaks
- **🆔 Unique IDs**: Cryptographically secure random IDs using nanoid

## Security Architecture

### Encryption Details

- **Key Derivation**: Argon2id with configurable parameters
  - Time cost: 2 iterations
  - Memory cost: 128 MiB
  - Parallelism: 4 threads
  - Output: 32-byte key
- **Encryption Algorithm**: AES-256-GCM (Galois/Counter Mode)
- **Key Wrapping**: Master password derives KEK (Key Encryption Key), which encrypts DEK (Data Encryption Key)
- **Nonce**: Unique 12-byte nonce for each encryption operation
- **Salt**: 16-byte random salt for key derivation

### How It Works

1. **Initialization**: Master password → Argon2id → KEK → Encrypts DEK → Stores wrapped DEK
2. **Unlock**: Master password → Argon2id → KEK → Decrypts DEK → Unlocks vault
3. **Entry Storage**: Password → AES-GCM (using DEK) → Base64-encoded ciphertext

## Installation

### Prerequisites

- Go 1.25.1 or higher
- Linux/macOS (clipboard support)

### Build from Source

```bash
git clone <repository-url>
cd vault
go build -o vault ./cmd/main.go
```

### Install

```bash
# Move to a directory in your PATH
sudo mv vault /usr/local/bin/
```

## Usage

### Initialize Vault

Create a new vault with a master password:

```bash
vault init
```

You'll be prompted to create and confirm a master password.

### Unlock Vault

Unlock the vault and enter interactive mode:

```bash
vault unlock
```

### Interactive Commands

Once unlocked, you can use the following commands:

#### Add Entry

```bash
vault> add <site> <username>
```

Example:
```bash
vault> add github.com john.doe
Enter entry password: ********
✅ Entry added successfully
```

#### Get Entry

Retrieve an entry by ID or site name (password copied to clipboard):

```bash
vault> get <id/site>
```

Example:
```bash
vault> get github.com
============================================================
Site:     github.com
Username: john.doe
------------------------------------------------------------
🔑 Password copied to clipboard.
============================================================
```

#### List Entries

Display all stored entries:

```bash
vault> list
============================================================
No.   | ID     | Site                     | Username            
------------------------------------------------------------
1     | abc123 | github.com               | john.doe            
2     | def456 | gitlab.com               | jane.smith          
------------------------------------------------------------
Total entries: 2
```

#### Remove Entry

Delete an entry by ID:

```bash
vault> remove <id>
```

Example:
```bash
vault> remove abc123
✅ Entry removed successfully.
```

#### Lock Vault

Lock the vault and exit:

```bash
vault> lock
🔒 Vault locked successfully.
```

## Project Structure

```
vault/
├── cmd/
│   └── main.go           # Main application entry point and CLI logic
├── internal/
│   ├── vault.go          # Cryptographic operations (Argon2, AES-GCM)
│   ├── io.go             # File I/O and password input handling
│   └── type.go           # Data structures (Vault, Entry)
├── go.mod                # Go module dependencies
├── go.sum                # Dependency checksums
├── LICENSE               # License file
└── README.md             # This file
```

## Dependencies

- **golang.org/x/crypto**: Argon2 key derivation
- **golang.org/x/term**: Secure password input
- **golang.design/x/clipboard**: Clipboard operations
- **github.com/sixafter/nanoid**: Cryptographically secure ID generation

## Data Storage

Vault data is stored in `~/.vault.json` with the following structure:

```json
{
  "salt": "base64-encoded-salt",
  "wrapped_dek": "base64-encoded-encrypted-dek",
  "nonce_dek": "base64-encoded-nonce",
  "version": "1.0.0",
  "created_at": 1234567890,
  "entries": [
    {
      "id": "abc123",
      "site": "example.com",
      "username": "user@example.com",
      "password": "base64-encoded-encrypted-password"
    }
  ]
}
```

**File Permissions**: The vault file is created with `0600` permissions (read/write for owner only).

## Security Best Practices

1. **Choose a Strong Master Password**: Use a long, unique passphrase
2. **Keep Backups**: Regularly backup `~/.vault.json` to a secure location
3. **Protect Your Master Password**: Never share or write down your master password
4. **Secure Your System**: Ensure your operating system is secure and up-to-date
5. **Lock When Done**: Always lock the vault when finished

## Limitations

- **No Cloud Sync**: All data is stored locally
- **Single User**: Designed for single-user use
- **No Password Recovery**: If you forget your master password, data cannot be recovered
- **Platform Support**: Currently supports Linux/macOS (clipboard functionality)

## Development

### Run Tests

```bash
go test ./...
```

### Build

```bash
go build -o vault ./cmd/main.go
```

### Code Structure

- **VaultService**: Handles all cryptographic operations
- **IOService**: Manages file I/O and user input
- **Interactive Mode**: REPL-style interface for vault operations

## License

See [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please ensure all security-related changes are thoroughly reviewed.

## Disclaimer

This is a personal password manager. While it uses industry-standard encryption, use at your own risk. Always maintain backups of your vault file.