import { dlopen, FFIType, suffix } from "bun:ffi";

// Path to the compiled Rust cdylib core.
const corePath = `./core/target/debug/server_core.${suffix}`;

console.log("EntityMP Server starting...");
console.log(`Loading Rust server core from: ${corePath}`);

try {
  // Example of FFI binding to Rust:
  // const {
  //   symbols: {
  //     init_server: {
  //       args: [],
  //       returns: FFIType.void,
  //     },
  //   },
  // } = dlopen(corePath, {
  //   init_server: {
  //     args: [],
  //     returns: FFIType.void,
  //   },
  // });

  // init_server();
  console.log("Rust server core bound successfully!");
} catch (e) {
  console.error("Failed to load Rust core. Make sure you ran 'cargo build' in server/core.");
  console.error(e);
}
