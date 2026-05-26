```md
EntityMP/
├── Cargo.toml               # Root Workspace file uniting all Rust crates
├── client/                  # (DLL) Client-side library injected into the game
│   ├── Cargo.toml           # crate-type = ["cdylib"]
│   └── src/
│       ├── lib.rs           # DllMain, DLL entry point
│       ├── hooks.rs         # Hooking/intercepting game functions (DirectX, logic)
│       ├── memory.rs        # Reading/writing game process memory
│       ├── network.rs       # Network communication with the server
│       └── ui.rs            # UI rendering integration (WebView2 / Ultralight)
├── server/                  # Server-side application (Rust Core + Bun/Node TS)
│   ├── core/                # Server core logic in Rust
│   │   ├── Cargo.toml       # crate-type = ["cdylib"]
│   │   └── src/lib.rs       # Exports functions via FFI for Bun to consume
│   ├── package.json         # Package manifest and configuration for the Bun server
│   └── src/                 # Server scripts written in TypeScript
│       └── index.ts         # Main entry point for the server
├── shared/                  # (LIB) Shared library used by both client and server
│   ├── Cargo.toml           # crate-type = ["lib"]
│   └── src/lib.rs           # Packet serialization, shared data types and structures
├── sdk/                     # (LIB) Reversal SDK containing game engine structures and memory offsets
│   ├── Cargo.toml
│   └── src/lib.rs           # Memory addresses, patterns, and reversed C++ classes
└── launcher/                # (EXE) Launcher tool to start the game and inject client.dll
├── Cargo.toml
└── src/main.rs          # Spawns the game process and injects client.dll
```