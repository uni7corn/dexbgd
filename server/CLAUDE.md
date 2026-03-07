# server - dexbgd TUI debugger

Rust TUI server for the dexbgd Android debugger. Connects to the JVMTI agent over an abstract Unix socket and provides an interactive terminal UI.

## Key files
- `src/app.rs` (~4600 lines): main app logic, event loop, command dispatch
- `src/protocol.rs`: `OutboundCommand` (server→agent) and `AgentMessage` (agent→server) enums
- `src/dex_patcher.rs`: DEX bytecode patching and RedefineClasses pipeline
- `src/dex_parser.rs`: APK/DEX loading (ZIP Central Directory parsing)
- `src/disassembler.rs`: Dalvik bytecode disassembly
- `src/tui/`: panel rendering
- `src/ai*.rs`: AI integration (Claude, Ollama)

## Run
```bash
cd server && cargo run
```
Config: `server/dexbgd.toml`
