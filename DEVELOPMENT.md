# qcow2-rs Development Guide

A comprehensive guide for developers working on the qcow2-rs library.

## Table of Contents

1. [Development Environment Setup](#development-environment-setup)
2. [Architecture Deep Dive](#architecture-deep-dive)
3. [API Patterns and Best Practices](#api-patterns-and-best-practices)
4. [Testing and Validation](#testing-and-validation)
5. [Performance Considerations](#performance-considerations)
6. [Extension and Contribution Guidelines](#extension-and-contribution-guidelines)
7. [Debugging and Troubleshooting](#debugging-and-troubleshooting)

## Development Environment Setup

### Prerequisites

```bash
# Install Rust toolchain (latest stable)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Install required system packages
# Ubuntu/Debian:
sudo apt-get install qemu-utils build-essential

# Fedora/RHEL:
sudo dnf install qemu-img gcc

# For io_uring support (Linux only)
sudo apt-get install liburing-dev  # Ubuntu/Debian
sudo dnf install liburing-devel    # Fedora/RHEL
```

### Development Commands

```bash
# Format code and run basic checks
cargo fmt && cargo clippy

# Build all targets including platform-specific features
cargo build --all-features

# Run full test suite with verbose output
RUST_LOG=debug cargo test -- --nocapture

# Test specific IO backend
cargo test uring_io --features="tokio-uring"

# Generate documentation with private items
cargo doc --no-deps --document-private-items --open

# Profile performance (requires cargo-flamegraph)
cargo install flamegraph
sudo cargo flamegraph --bin rqcow2 -- info test.qcow2
```

## Architecture Deep Dive

### Core Module Hierarchy

```
qcow2-rs
├── meta.rs        - qcow2 format structures and metadata handling
├── dev.rs         - Device abstraction and core operations  
├── ops.rs         - IO backend trait definition
├── cache.rs       - Async LRU cache for metadata
├── helpers.rs     - Utilities and aligned memory management
├── error.rs       - Error types and handling
├── utils.rs       - Device setup utilities
├── tokio_io.rs    - Tokio async file backend
├── uring.rs       - Linux io_uring backend
├── sync_io.rs     - Synchronous IO backend
└── main.rs        - CLI utility implementation
```

### Data Structure Relationships

```rust
Qcow2Dev<T: Qcow2IoOps>
├── header: AsyncRwLock<Qcow2Header>
├── l1table: AsyncRwLock<L1Table>
├── l2cache: AsyncLruCache<usize, L2TableHandle>
├── reftable: AsyncRwLock<RefTable>
├── refblock_cache: AsyncLruCache<usize, AsyncRwLock<RefBlock>>
├── new_cluster: AsyncRwLock<HashMap<u64, AsyncRwLock<bool>>>
└── io_ops: T
```

### Lock Hierarchy and Safety

**Critical Lock Ordering (to prevent deadlocks):**
1. `flush_lock` (outermost)
2. `header` or `l1table` or `reftable`
3. Cache entries (`l2cache`, `refblock_cache`)
4. `new_cluster` per-cluster locks (innermost)

**Safe Patterns:**
```rust
// GOOD: Proper lock ordering
let _flush = self.flush_lock.lock().await;
let header = self.header.read().await;
let l2_handle = self.l2cache.get(index).await?;

// AVOID: Reverse ordering can deadlock
let l2_handle = self.l2cache.get(index).await?;
let header = self.header.read().await; // Potential deadlock!
```

### Memory Management Strategy

**Aligned Buffer Allocation:**
```rust
// Always use Qcow2IoBuf for IO operations
let mut buf = Qcow2IoBuf::<u8>::new(size);
assert_eq!(buf.as_ptr() as usize % 4096, 0); // 4KB aligned

// Direct slice access for performance-critical paths
let slice = unsafe { buf.as_mut_slice() };
```

**Cache Lifecycle:**
- **Entry Creation**: Cache miss triggers async load from disk
- **Dirty Tracking**: Modifications mark entries as dirty
- **Eviction**: LRU eviction with dirty entry flush
- **Manual Control**: Explicit cache flushing for consistency

## API Patterns and Best Practices

### Device Setup Patterns

```rust
use qcow2_rs::*;

// Basic setup with tokio backend
let params = qcow2_default_params!(false, false); // read-write, buffered IO
let dev = utils::qcow2_setup_dev_tokio(&path, &params).await?;

// High-performance setup with io_uring (Linux only)
#[cfg(target_os = "linux")]
{
    let params = qcow2_default_params!(false, true); // read-write, direct IO
    let dev = utils::qcow2_setup_dev_uring(&path, &params).await?;
}

// Read-only setup
let params = qcow2_default_params!(true, false); // read-only, buffered IO
let dev = utils::qcow2_setup_dev_tokio(&path, &params).await?;
```

### IO Operation Patterns

**Aligned Buffer Management:**
```rust
// Cluster-aligned operations for best performance
let cluster_size = dev.info.cluster_size();
let mut buf = Qcow2IoBuf::<u8>::new(cluster_size);

// Read full cluster
let offset = 0; // Must be cluster-aligned for direct IO
let bytes_read = dev.read_at(&mut buf, offset).await?;

// Partial reads require careful offset handling
let partial_offset = 1024; // Non-aligned offset
let partial_size = 2048;
let mut partial_buf = Qcow2IoBuf::<u8>::new(partial_size);
let bytes_read = dev.read_at(&mut partial_buf, partial_offset).await?;
```

**Batch Operations:**
```rust
// Efficient bulk operations
let operations = vec![
    (offset1, data1),
    (offset2, data2),
    (offset3, data3),
];

for (offset, data) in operations {
    dev.write_at(&data, offset).await?;
}

// Flush metadata once after batch
if dev.need_flush_meta() {
    dev.flush_meta().await?;
}
```

### Error Handling Patterns

```rust
use qcow2_rs::error::Qcow2Error;

// Standard error propagation
async fn my_operation() -> qcow2_rs::error::Qcow2Result<()> {
    let dev = setup_device().await?;
    let data = prepare_data()?;
    dev.write_at(&data, 0).await?;
    dev.flush_meta().await?;
    Ok(())
}

// Custom error context
fn validate_input(path: &Path) -> qcow2_rs::error::Qcow2Result<()> {
    if !path.exists() {
        return Err(Qcow2Error::from(format!("File not found: {:?}", path)));
    }
    Ok(())
}
```

### Async Patterns

**Concurrent Operations:**
```rust
use futures::future::try_join_all;

// Parallel reads from different offsets
let read_futures = offsets.into_iter().map(|offset| {
    let dev = &dev;
    async move {
        let mut buf = Qcow2IoBuf::<u8>::new(cluster_size);
        dev.read_at(&mut buf, offset).await
    }
});

let results = try_join_all(read_futures).await?;
```

**Resource Management:**
```rust
// RAII pattern for cache management
struct DeviceGuard<T> {
    dev: Qcow2Dev<T>,
}

impl<T> DeviceGuard<T> {
    async fn new(path: &Path) -> qcow2_rs::error::Qcow2Result<Self> {
        let params = qcow2_default_params!(false, false);
        let dev = utils::qcow2_setup_dev_tokio(path, &params).await?;
        Ok(Self { dev })
    }
}

impl<T> Drop for DeviceGuard<T> {
    fn drop(&mut self) {
        // Cache is automatically flushed via RAII
    }
}
```

## Testing and Validation

### Test Categories

**Unit Tests (`tests/basic.rs`):**
```bash
# Basic functionality tests
cargo test test_format_qcow2
cargo test test_compress_read_write

# Run with different cluster sizes
CLUSTER_BITS=16 cargo test
CLUSTER_BITS=20 cargo test  # 1MB clusters
```

**IO Backend Tests:**
```bash
# Test tokio backend
cargo test sync_io

# Test io_uring backend (Linux only)
cargo test uring_io

# Cross-platform compatibility
cargo test --all-features
```

**Integration Tests:**
```bash
# Compatibility with qemu-img
qemu-img create -f qcow2 test.qcow2 1G
cargo run -- check test.qcow2
cargo run -- info test.qcow2

# Round-trip conversion testing
cargo run -- convert -f raw -O qcow2 -o test.qcow2 /dev/zero
cargo run -- convert -f qcow2 -O raw -o test.raw test.qcow2
```

### Custom Test Setup

```rust
use tempfile::NamedTempFile;
use qcow2_rs::*;

#[tokio::test]
async fn test_custom_scenario() -> qcow2_rs::error::Qcow2Result<()> {
    // Create temporary qcow2 file
    let tmp = NamedTempFile::new()?;
    let params = Qcow2DevParams::new(16, None, None, false, false); // 64KB clusters
    
    // Format the file
    let size = 64 << 20; // 64MB
    let mut file = std::fs::File::create(tmp.path())?;
    let buf = create_qcow2_image(size, 16, 4)?;
    file.write_all(&buf)?;
    drop(file);
    
    // Test operations
    let dev = utils::qcow2_setup_dev_tokio(tmp.path(), &params).await?;
    
    // Your test logic here
    let mut data = Qcow2IoBuf::<u8>::new(4096);
    data.fill(0x42);
    dev.write_at(&data, 0).await?;
    
    let mut read_buf = Qcow2IoBuf::<u8>::new(4096);
    let bytes_read = dev.read_at(&mut read_buf, 0).await?;
    assert_eq!(bytes_read, 4096);
    assert_eq!(read_buf[0], 0x42);
    
    Ok(())
}
```

### Debugging Test Failures

```bash
# Enable detailed logging
RUST_LOG=qcow2_rs=debug cargo test test_name -- --nocapture

# Test with specific parameters
CLUSTER_BITS=18 REFCOUNT_ORDER=4 cargo test

# Memory leak detection (requires valgrind)
valgrind --tool=memcheck --leak-check=full \
    cargo test --release test_name

# Performance profiling
cargo test --release test_name -- --profile-time 10
```

## Performance Considerations

### IO Backend Selection

**Performance Characteristics:**
- **tokio_io**: Best compatibility, moderate performance
- **uring**: Highest performance on Linux, requires kernel 5.1+
- **sync_io**: Lowest latency for single operations

**Benchmark Patterns:**
```rust
use std::time::Instant;

async fn benchmark_reads(dev: &Qcow2Dev<impl Qcow2IoOps>) {
    let cluster_size = dev.info.cluster_size();
    let mut buf = Qcow2IoBuf::<u8>::new(cluster_size);
    
    let start = Instant::now();
    for i in 0..1000 {
        let offset = (i * cluster_size) as u64;
        dev.read_at(&mut buf, offset).await.unwrap();
    }
    let duration = start.elapsed();
    
    println!("Read 1000 clusters in {:?}", duration);
    println!("Throughput: {:.2} MB/s", 
        (1000 * cluster_size) as f64 / duration.as_secs_f64() / 1024.0 / 1024.0);
}
```

### Memory Optimization

**Cache Tuning:**
```rust
let params = Qcow2DevParams {
    cluster_bits: 16,           // 64KB clusters
    l2_cache_entries: Some(32), // Limit L2 cache size
    refcount_cache_entries: Some(16),
    read_only: false,
    direct_io: true,
};
```

**Memory-Mapped Access (for large files):**
```rust
// Consider memory mapping for read-heavy workloads
use memmap2::MmapOptions;

let file = std::fs::File::open(&path)?;
let mmap = unsafe { MmapOptions::new().map(&file)? };

// Use mmap for metadata-only operations
// But prefer regular IO for data operations
```

### Cluster Allocation Optimization

**Sequential Allocation Pattern:**
```rust
// Allocate clusters in sequence for better disk layout
let cluster_count = 8; // Allocate multiple clusters at once
if let Some((start_offset, allocated_count)) = 
    dev.allocate_clusters(cluster_count).await? {
    
    // Use allocated clusters sequentially
    for i in 0..allocated_count {
        let cluster_offset = start_offset + (i as u64 * cluster_size as u64);
        // Use cluster_offset for data placement
    }
}
```

## Extension and Contribution Guidelines

### Adding New IO Backends

1. **Implement the `Qcow2IoOps` trait:**

```rust
use async_trait::async_trait;

pub struct MyCustomIoOps {
    // Your custom fields
}

#[async_trait]
impl Qcow2IoOps for MyCustomIoOps {
    async fn read_to(&self, offset: u64, buf: &mut [u8]) -> Qcow2Result<usize> {
        // Your implementation
    }
    
    async fn write_from(&self, offset: u64, buf: &[u8]) -> Qcow2Result<()> {
        // Your implementation
    }
    
    async fn fallocate(&self, offset: u64, len: usize, flags: u32) -> Qcow2Result<()> {
        // Optional: implement for better performance
        // Fallback to zero-writes if not supported
        Ok(())
    }
    
    async fn fsync(&self, offset: u64, len: usize, flags: u32) -> Qcow2Result<()> {
        // Your sync implementation
        Ok(())
    }
}
```

2. **Add setup utility function:**

```rust
pub async fn qcow2_setup_dev_custom(
    path: &Path, 
    params: &Qcow2DevParams
) -> Qcow2Result<Qcow2Dev<MyCustomIoOps>> {
    let io_ops = MyCustomIoOps::new(path).await?;
    let dev = Qcow2Dev::new(io_ops, path, params).await?;
    Ok(dev)
}
```

### Adding New qcow2 Features

**Header Extensions:**
```rust
// Add support for new qcow2 header extensions
impl Qcow2Header {
    pub fn parse_custom_extension(&self, ext_type: u32) -> Option<CustomExtension> {
        for ext in &self.extensions {
            if ext.ext_type == ext_type {
                return CustomExtension::parse(&ext.data);
            }
        }
        None
    }
}
```

**Feature Flags:**
```rust
// Add new feature detection
impl Qcow2Header {
    pub fn supports_custom_feature(&self) -> bool {
        self.incompatible_features & CUSTOM_FEATURE_MASK != 0
    }
}
```

### Code Style Guidelines

**Naming Conventions:**
- Use `snake_case` for functions and variables
- Use `PascalCase` for types and traits
- Use `SCREAMING_SNAKE_CASE` for constants
- Prefix private functions with `__` for internal helpers

**Documentation Standards:**
```rust
/// Brief description of function purpose
/// 
/// # Arguments
/// 
/// * `param1` - Description of first parameter
/// * `param2` - Description of second parameter
/// 
/// # Returns
/// 
/// Description of return value and any special cases
/// 
/// # Errors
/// 
/// Description of possible error conditions
/// 
/// # Examples
/// 
/// ```rust
/// let result = function_name(arg1, arg2).await?;
/// ```
pub async fn function_name(param1: Type1, param2: Type2) -> Qcow2Result<ReturnType> {
    // Implementation
}
```

**Error Handling:**
```rust
// Prefer early returns with ?
if condition {
    return Err("Descriptive error message".into());
}

// Use context for error chains
operation().await
    .map_err(|e| format!("Failed to perform operation: {}", e))?;
```

### Performance Testing

**Benchmark Suite:**
```rust
use criterion::{criterion_group, criterion_main, Criterion};

fn benchmark_read_operations(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    
    c.bench_function("sequential_reads", |b| {
        b.iter(|| {
            rt.block_on(async {
                // Your benchmark code
            })
        })
    });
}

criterion_group!(benches, benchmark_read_operations);
criterion_main!(benches);
```

## Debugging and Troubleshooting

### Logging Configuration

```rust
// Enable detailed logging
use log::{debug, info, warn, error};

// In your code
debug!("Processing cluster at offset {:#x}", offset);
info!("Allocated {} clusters starting at {:#x}", count, start_offset);
warn!("Cache miss for L2 table {}", index);
error!("Failed to allocate cluster: {}", error);
```

```bash
# Runtime logging control
RUST_LOG=qcow2_rs=debug ./your_program
RUST_LOG=qcow2_rs::dev=trace ./your_program
RUST_LOG=debug ./your_program  # All debug output
```

### Common Issues and Solutions

**1. Alignment Errors:**
```
Error: "Invalid buffer alignment"
Solution: Use Qcow2IoBuf instead of Vec<u8> for IO operations
```

**2. Deadlock Detection:**
```rust
// Add timeout to lock operations
use tokio::time::{timeout, Duration};

let result = timeout(Duration::from_secs(5), 
    self.header.read()).await;

match result {
    Ok(guard) => { /* use guard */ },
    Err(_) => return Err("Lock timeout - possible deadlock".into()),
}
```

**3. Cache Thrashing:**
```
Symptoms: High CPU usage, poor performance
Solution: Increase cache sizes in Qcow2DevParams
```

**4. File Corruption:**
```bash
# Validate qcow2 file integrity
cargo run -- check suspicious_file.qcow2

# Compare with qemu-img
qemu-img check suspicious_file.qcow2
```

### Debug Utilities

**Memory Usage Analysis:**
```rust
use std::alloc::{GlobalAlloc, Layout, System};

// Track allocations
static ALLOCATOR: TracingAllocator = TracingAllocator;

struct TracingAllocator;

unsafe impl GlobalAlloc for TracingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ptr = System.alloc(layout);
        println!("Allocated {} bytes at {:p}", layout.size(), ptr);
        ptr
    }
    
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        println!("Deallocated {} bytes at {:p}", layout.size(), ptr);
        System.dealloc(ptr, layout);
    }
}
```

**Cache Statistics:**
```rust
// Add to Qcow2Dev implementation
impl<T> Qcow2Dev<T> {
    pub fn cache_stats(&self) -> CacheStats {
        CacheStats {
            l2_hit_rate: self.l2cache.hit_rate(),
            refblock_hit_rate: self.refblock_cache.hit_rate(),
            dirty_entries: self.l2cache.dirty_count(),
        }
    }
}
```

This development guide provides the foundation for contributing to and extending qcow2-rs. For specific questions or advanced use cases, refer to the source code documentation and test cases for detailed examples.