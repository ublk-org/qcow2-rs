# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

qcow2-rs is a Rust library for reading/writing qcow2 (QEMU Copy On Write) disk images. It provides async/await support with multiple IO engines including tokio-uring, Linux sync IO, and tokio.

## Common Commands

### Build and Test
```bash
# Build the library and binary
cargo build

# Build in release mode
cargo build --release

# Run tests (requires qemu-img to be installed)
cargo test

# Run specific test
cargo test basic

# Run uring-specific tests (Linux only)
cargo test uring_io

# Run sync IO tests
cargo test sync_io
```

### Utility Commands (rqcow2 binary)
```bash
# Show qcow2 image info and statistics
cargo run -- info <image.qcow2>

# Dump qcow2 metadata structures
cargo run -- dump --l1-table --l2-table <image.qcow2>

# Check image integrity
cargo run -- check <image.qcow2>

# Format new qcow2 image (64MB, 64KB clusters)
cargo run -- format --size 64 --cluster-bits 16 <new-image.qcow2>

# Convert between qcow2 and raw formats
cargo run -- convert -f qcow2 -O raw -o output.raw input.qcow2
cargo run -- convert -f raw -O qcow2 -o output.qcow2 input.raw
```

### Linting and Code Quality
```bash
# Format code
cargo fmt

# Run clippy lints
cargo clippy
```

## Architecture

### Core Components

- **src/lib.rs**: Main library exports and module declarations
- **src/main.rs**: CLI utility (`rqcow2`) with subcommands for dump, info, format, check, map, and convert
- **src/dev.rs**: Core device abstraction (`Qcow2Dev`) and device info (`Qcow2Info`)
- **src/meta.rs**: qcow2 metadata structures (headers, L1/L2 tables, refcount tables)
- **src/ops.rs**: IO operation traits (`Qcow2IoOps`) for different async runtimes
- **src/cache.rs**: LRU cache implementation for metadata
- **src/error.rs**: Error handling types

### IO Backends

- **src/uring.rs**: Linux io_uring backend via tokio-uring (Linux only)
- **src/tokio_io.rs**: Standard tokio async IO backend  
- **src/sync_io.rs**: Synchronous IO backend (non-Windows)

### Utilities

- **src/helpers.rs**: Helper types including `Qcow2IoBuf` for aligned IO buffers
- **src/utils.rs**: Utility functions for setting up devices with different backends

### Test Structure

- **tests/basic.rs**: Basic functionality tests
- **tests/sync_io.rs**: Synchronous IO tests
- **tests/uring_io.rs**: io_uring specific tests  
- **tests/qcow2_util.rs**: qcow2 utility testing
- **tests/common/**: Shared test utilities

## Key Design Patterns

### Multi-Runtime Support
The library abstracts IO operations through the `Qcow2IoOps` trait, allowing the same code to work with:
- tokio-uring (Linux, direct IO)
- tokio (cross-platform, buffered IO)
- Raw sync syscalls (Linux/FreeBSD)

### Async Metadata Management
- L2 tables and refcount blocks are loaded/stored in slice units (block size to cluster size)
- LRU caching for frequently accessed metadata
- Soft update style for lazy metadata flushing

### Memory-Aligned IO
Uses `Qcow2IoBuf<T>` for properly aligned IO buffers required by direct IO operations.

## Platform Support

- Linux: Full support including io_uring
- Windows: Limited to tokio backend (no sync_io)
- FreeBSD: tokio and sync_io backends

## Dependencies

Key external dependencies:
- `tokio`: Async runtime (with "full" features)
- `tokio-uring`: Linux io_uring support
- `clap`: CLI argument parsing
- `serde`/`bincode`: Serialization for metadata structures
- `miniz_oxide`: Compression support
- `futures-locks`: Async locking primitives