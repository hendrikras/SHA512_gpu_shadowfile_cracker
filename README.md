# GPU Password Cracker

A high-performance password recovery tool with Metal GPU acceleration for Apple Silicon Macs.

## Features

- 🚀 **Metal GPU Acceleration** - Optimized for Apple M1/M2/M3/M4 processors
- 💻 **CPU Fallback** - Automatic fallback to multi-threaded CPU processing
- 🎯 **Mask Attack** - Pattern-based brute force with customizable character sets
- 📋 **Wordlist Attack** - Dictionary-based password cracking
- ~~📊 **Progress Tracking** - Real-time progress bars and statistics~~
- 🔒 **SHA512 Crypt Support** - Targets SHA512-based Unix password hashes

## Installation

### Prerequisites

- **macOS** with Apple Silicon (M1/M2/M3/M4) for GPU acceleration
- **Rust** toolchain (install from [rustup.rs](https://rustup.rs/))
- **Metal framework** (included with macOS)

### Build

```bash
  cargo build --release
```

## Usage

### Basic Syntax

```bash
  gpu_password_cracker --hash <HASH_SOURCE> [MODE] [OPTIONS]
```

### Command Line Options

#### Required Arguments

| Option | Description |
|--------|-------------|
| `-H, --hash <HASH>` | Path to shadow file or direct hash string |

#### Attack Modes (Choose One)

| Option | Description | Example |
|--------|-------------|---------|
| `-w, --wordlist <FILE>` | Path to wordlist file | `--wordlist rockyou.txt` |
| `-m, --mask <PATTERN>` | Mask pattern for brute force | `--mask "?l?l?l?d?d?d"` |

#### Optional Arguments

| Option | Description | Default |
|--------|-------------|---------|
| `-g, --gpu` | Enable GPU acceleration (Metal) | CPU only |
| `-t, --threads <NUM>` | Number of CPU threads | All available cores |
| `-u, --username <USER>` | Target specific user from shadow file | First user found |
| `-p, --progress-file <FILE>` | Progress file for resuming | None |
| `-h, --help` | Show help message | - |

## Attack Modes

### 1. Wordlist Attack

Use a dictionary file containing potential passwords:

```bash
# Basic wordlist attack
./gpu_password_cracker --hash /etc/shadow --wordlist rockyou.txt --username root

# With GPU acceleration
./gpu_password_cracker --hash /etc/shadow --wordlist passwords.txt --username admin --gpu
```

### 2. Mask Attack

Use pattern-based brute force with mask characters:

#### Mask Characters

| Character | Represents | Example                       |
|-----------|------------|-------------------------------|
| `?l` | Lowercase letters (a-z) | `abc...xyz`                   |
| `?u` | Uppercase letters (A-Z) | `ABC...XYZ`                   |
| `?d` | Digits (0-9) | `0123456789`                  |
| `?s` | Special characters | `!@#$%^&*()_+-=[]{}\|;:,.<>?` |
| `?a` | All printable ASCII | `?l + ?u + ?d + ?s`           |
| `??` | Literal question mark | `?`                           |
| Any other char | Literal character | `abc123`                      |

#### Mask Examples

```bash
    # 4-digit PIN
    ./gpu_password_cracker --hash shadow.txt --mask "?d?d?d?d" --username user
    
    # 6-character lowercase
    ./gpu_password_cracker --hash shadow.txt --mask "?l?l?l?l?l?l" --username user
    
    # Mixed pattern: "admin" + 3 digits
    ./gpu_password_cracker --hash shadow.txt --mask "admin?d?d?d" --username user
    
    # Password + year pattern
    ./gpu_password_cracker --hash shadow.txt --mask "password?d?d?d?d" --username user
    
    # Complex pattern with special chars
    ./gpu_password_cracker --hash shadow.txt --mask "?l?l?l?d?d!" --username user
```

## Input Formats

### Shadow File Format

Standard Unix shadow file format:
```
username:$6$salt$hash:18902:0:99999:7:::
root:$6$TjTc8/T6fSm0t9if$6/Q19TlzieCUPefZbEaozS3y98Usf2GBToOWIAMN/7Ia1j75xLp6PCnmuVTbUiLsUEDj7wrvihr6RdanzIqCr1:20321:0:99999:7:::
```

### Direct Hash Input

Pass hash directly as argument:
```bash
  ./gpu_password_cracker --hash '$6$salt$hash...' --mask "?d?d?d?d"
```

## Performance

### GPU Acceleration (Metal)

- **Device:** Apple M4 Max (or other Apple Silicon)
- **Framework:** Metal compute shaders
- **Batch Size:** 8,192 passwords per GPU kernel launch
- **Memory:** Shared GPU/CPU memory for efficient transfers

### CPU Fallback

- **Threading:** Rayon parallel processing
- **Cores:** Utilizes all available CPU cores by default
- **Library:** sha-crypt for SHA512 verification

### Benchmarks

*Performance varies based on hardware and pattern complexity*

| Mode | Hardware | Rate | Notes |
|------|----------|------|-------|
| Wordlist | M4 Max CPU | ~350-400 attempts/sec | Real SHA512 verification |
| Mask | M4 Max CPU | ~350-400 attempts/sec | Generated passwords |
| GPU | M4 Max GPU | Limited by SHA512 | Placeholder implementation |

## Examples

### Common Scenarios

#### 1. Crack root password with 4-digit PIN
```bash
  ./gpu_password_cracker --hash /etc/shadow --mask "?d?d?d?d" --username root --gpu
```

#### 2. Try passwords ending with current year
```bash
  ./gpu_password_cracker --hash shadow.txt --mask "?l?l?l?l?l2024" --username admin
```

#### 3. Use wordlist with specific user
```bash
  ./gpu_password_cracker --hash /etc/shadow --wordlist common_passwords.txt --username john
```

#### 4. Multi-threaded CPU attack
```bash
  ./gpu_password_cracker --hash shadow.txt --mask "?l?l?l?l" --threads 8
```

## Output

### Success Output
```
🎉 PASSWORD FOUND!
User: root
Password: abc1234!
Time taken: 20.80s
Attempts: 7443
Rate: 358 attempts/sec
```

### Failure Output
```
❌ Password not found using mask pattern
Time taken: 49.84s
Total attempts: 17576
Rate: 353 attempts/sec
```

## Technical Details

### Supported Hash Types

- **SHA512 Crypt** (`$6$...`) - Standard Unix/Linux password hashes
- **Rounds:** Supports custom round counts (default: 5000)

### Memory Management

- **Small patterns** (< 1M combinations): Load all into memory
- **Large patterns** (≥ 1M combinations): Batch processing (100k per batch)
- **GPU batches:** 8,192 passwords per Metal kernel execution

### GPU Implementation

- **Language:** Metal Shading Language (MSL)
- **Compute Kernels:** Parallel password verification
- **Atomic Operations:** Thread-safe result sharing
- **Fallback:** Automatic CPU fallback on GPU errors

## Limitations

- **GPU SHA512:** This is **experimental feature** and comes with no warranty.
- **Hash Types:** Only supports SHA512 crypt format
- **Platform:** Metal GPU acceleration requires Apple Silicon Macs
- **Memory:** Large wordlists may consume significant RAM
- **Progress tracking:** Currently disabled.

## Development

### Project Structure

```
src/
├── main.rs              # CLI interface and main logic
├── cpu_cracker.rs       # CPU-based password cracking
├── gpu_cracker_metal.rs # Metal GPU implementation
├── mask.rs              # Mask pattern generation
├── wordlist.rs          # Wordlist loading utilities
└── progress.rs          # Progress tracking (unused)
```

### Building for Release

```bash
    cargo build --release
    ./target/release/gpu_password_cracker --help
```

### Testing

```bash
    # Run all tests
    cargo test
    
    # Test mask generation only
    cargo test mask
    
    # Test wordlist loading
    cargo test wordlist
```

## Security Notice

⚠️ **This tool is for legitimate security testing and educational purposes only.**

- Only use on systems you own or have explicit permission to test
- Respect all applicable laws and regulations
- Consider rate limiting for production systems
- Use responsibly and ethically

## Troubleshooting

### GPU Issues

**Problem:** GPU acceleration fails
```
⚠️ GPU acceleration failed: Failed to compile Metal shader
```

**Solutions:**
- Ensure you're on Apple Silicon Mac (M1/M2/M3/M4)
- Update to latest macOS version
- Tool will automatically fallback to CPU

### Memory Issues

**Problem:** Out of memory with large patterns
```
Error: Mask pattern generates X combinations - too large for memory
```

**Solutions:**
- Pattern automatically uses batch processing for >1M combinations
- Reduce pattern complexity if needed
- Monitor system memory usage

### Performance Issues

**Problem:** Slow cracking speed

**Solutions:**
- Use `--gpu` flag for GPU acceleration
- Increase `--threads` for more CPU cores
- Use more targeted mask patterns
- Consider smaller search spaces first

## License

MIT
