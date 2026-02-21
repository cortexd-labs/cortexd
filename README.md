# cortexd

`cortexd` is an AI-native Linux infrastructure intelligence layer. It securely maps real-time `/proc`, `systemctl`, and `journalctl` telemetry securely into the Model Context Protocol (MCP) using a single, unified Rust daemon.

This repository is the core server (`stdio` transport) allowing AI models like Claude to instantly observe their host operating environment.

## 🚀 Getting Started (for Contributors)

### 1. Prerequisites

- **Rust Toolchain**: 1.70+ recommended (`curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh`)
- **systemd**: Must be running on a modern Linux host to map `service.*` and `log.*` providers.

### 2. Building & Testing Make sure to strictly enforce `cargo clippy` and handle all `Result` errors idiomatically before opening a PR.

```bash
# Clone the repository
git clone https://github.com/cortexd-labs/cortexd.git
cd cortexd

# Run the 20 test suite mappings against the raw Linux kernel endpoints
cargo test

# Ensure strict styling and typing compliance
cargo clippy --all-targets --all-features -- -D warnings

# Build the final release binary
cargo build --release
```

## 🛠️ Testing with an AI Client

Because `cortexd` speaks the Model Context Protocol natively over `stdin/stdout`, you can instantly test it with any MCP-compliant interface.

### The MCP Inspector (Recommended for Dev)

If you have Node.js / `npm` installed, the easiest way to debug your Rust changes interactively is the official web-inspector.

From the root `cortexd` directory, run:

```bash
npx -y @modelcontextprotocol/inspector cargo run
```

This will open a local webport (e.g. `http://localhost:5173`) where you can manually trigger `tools/call` for `process.top`, `system.info`, etc., and see the exact JSON-RPC payloads mapping from the daemon.

### Claude Desktop

To hook the daemon directly into Claude Desktop on your Linux host:

1. Build the release binary: `cargo build --release`
2. Add the path to your Claude Config: `~/.config/Claude/claude_desktop_config.json`

```json
{
  "mcpServers": {
    "cortexd": {
      "command": "/absolute/path/to/cortexd/target/release/cortexd"
    }
  }
}
```

3. Restart Claude Desktop. It will now have the ability to observe your system in real-time.

## 🏗️ Architecture

The project intentionally uses a single-crate MVP structure for maximum DevX loop velocity:

- `src/core/`: The `Provider` traits and central `ProviderRegistry`.
- `src/transport/`: The `mcp.rs` stdio JSON-RPC loop handlers.
- `src/providers/`: The individual spec mappings (`system`, `process`, `service`, `log`).
- `src/linux/`: The raw subsystem polling functions mapping `systemctl` and `/proc`.

## Contributing

1. Implement new Providers under `src/providers`.
2. Map new system boundaries cleanly in `src/linux` via the `execute_command_stdout` or `read_proc_file` helpers.
3. Write `#[cfg(test)]` blocks validating your mapping logic.
4. Ensure `cargo clippy` is fully warning-free.
