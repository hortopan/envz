# envz

Secure environment variable management for macOS. Encrypts secrets at rest using AES-256-GCM and stores decryption keys in your macOS Keychain with optional Touch ID authentication.

## Why envz?

In the age of AI agents and LLMs, your environment variables are more exposed than ever. Coding assistants, shell agents, and dev tools routinely have access to your terminal session — and with it, every secret sitting in a plaintext `.env` file. One careless API call from an agent and your keys are sent to a third party.

**envz** was built to fix this. Secrets are encrypted at rest, decrypted in-memory only when needed, and never exposed to processes that don't need them. The `unsafe` command lets you run untrusted tools (like LLM agents) in a sanitized environment where your secrets simply don't exist.

- **AES-256-GCM encryption** — secrets never stored as plaintext
- **OS Keychain storage** — decryption keys live in macOS Keychain
- **Touch ID support** — optional biometric authentication on macOS
- **Process isolation** — inject secrets only into the processes that need them
- **Safe mode** — run untrusted commands (LLM agents, scripts) with filtered environment variables

> **Platform:** macOS only (requires Keychain and optionally Touch ID)

## Installation

### Homebrew

```bash
brew install hortopan/tap/envz
```

### From releases

Download the latest binary from [GitHub Releases](https://github.com/hortopan/envz/releases).

### From source

```bash
cargo install --path .
```

### With code signing (for Keychain access)

```bash
./scripts/build_macos.sh
sudo cp target/release/envz /usr/local/bin/
```

## Quick start

```bash
# Initialize a new vault in the current directory
envz init

# Import from an existing .env file
envz init .env

# Add secrets
envz set DATABASE_URL="postgres://localhost/mydb"
envz set API_KEY="sk-secret-key"

# View secrets
envz list
envz get DATABASE_URL

# Run a command with secrets injected
envz run -- npm start
envz run -- docker compose up

# Load into current shell
source <(envz env)

# Unload from current shell
source <(envz unenv)
```

## Commands

| Command | Description |
|---|---|
| `envz init [file]` | Initialize a new vault, optionally importing from a `.env` file |
| `envz set KEY=VALUE` | Set an environment variable |
| `envz get KEY` | Get the value of a variable |
| `envz delete KEY` | Delete a variable |
| `envz list` | List all variables and values |
| `envz clear` | Remove all variables from the vault |
| `envz run -- <cmd>` | Run a command with vault variables injected |
| `envz env` | Output `export` statements for shell sourcing |
| `envz unenv` | Output `unset` statements to remove variables |
| `envz unsafe -- <cmd>` | Run a command with only safe system environment variables |

### Options

- `--no-biometric` — disable Touch ID during `init`
- `--force` — overwrite existing vault during `init`

## Security model

- Secrets are encrypted with **AES-256-GCM** (authenticated encryption)
- Each encryption uses a unique random 12-byte nonce
- The master key is stored in the **macOS Keychain**, not on disk
- The vault is bound to its absolute path (moving it invalidates it)
- Decryption happens in-memory only — secrets are never written to disk unencrypted
- Sensitive memory is zeroized after use

### The `unsafe` command

The `unsafe` command runs a process with a minimal, curated set of environment variables (PATH, HOME, SHELL, TERM, etc.), stripping out anything that could leak secrets. This is useful for running LLM agents or untrusted scripts safely.

## How it works

```
┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│  .envz file  │────>│  AES-256-GCM │────>│  Plaintext   │
│  (encrypted) │     │  decryption  │     │  (in-memory) │
└──────────────┘     └──────┬───────┘     └──────────────┘
                            │
                     ┌──────┴───────┐
                     │ macOS        │
                     │ Keychain     │
                     │ (master key) │
                     └──────────────┘
```

## License

[MIT](LICENSE) — Alex Hortopan
