
use crate::HashTarget;
use anyhow::{anyhow, Result};
use indicatif::ProgressBar;
use metal::*;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

const SHA512_CRYPT_SHADER: &str = r#"
#include <metal_stdlib>
using namespace metal;

struct GpuPassword {
    char password[64];
    int password_len;
};

struct GpuTarget {
    char hash[129];
    char salt[32];
    int rounds;
};

struct GpuResult {
    atomic_int found;
    int index;
    char password[64];
};

// SHA-512 constants
constant ulong K[80] = {
    0x428a2f98d728ae22UL, 0x7137449123ef65cdUL, 0xb5c0fbcfec4d3b2fUL, 0xe9b5dba58189dbbcUL,
    0x3956c25bf348b538UL, 0x59f111f1b605d019UL, 0x923f82a4af194f9bUL, 0xab1c5ed5da6d8118UL,
    0xd807aa98a3030242UL, 0x12835b0145706fbeUL, 0x243185be4ee4b28cUL, 0x550c7dc3d5ffb4e2UL,
    0x72be5d74f27b896fUL, 0x80deb1fe3b1696b1UL, 0x9bdc06a725c71235UL, 0xc19bf174cf692694UL,
    0xe49b69c19ef14ad2UL, 0xefbe4786384f25e3UL, 0x0fc19dc68b8cd5b5UL, 0x240ca1cc77ac9c65UL,
    0x2de92c6f592b0275UL, 0x4a7484aa6ea6e483UL, 0x5cb0a9dcbd41fbd4UL, 0x76f988da831153b5UL,
    0x983e5152ee66dfabUL, 0xa831c66d2db43210UL, 0xb00327c898fb213fUL, 0xbf597fc7beef0ee4UL,
    0xc6e00bf33da88fc2UL, 0xd5a79147930aa725UL, 0x06ca6351e003826fUL, 0x142929670a0e6e70UL,
    0x27b70a8546d22ffcUL, 0x2e1b21385c26c926UL, 0x4d2c6dfc5ac42aedUL, 0x53380d139d95b3dfUL,
    0x650a73548baf63deUL, 0x766a0abb3c77b2a8UL, 0x81c2c92e47edaee6UL, 0x92722c851482353bUL,
    0xa2bfe8a14cf10364UL, 0xa81a664bbc423001UL, 0xc24b8b70d0f89791UL, 0xc76c51a30654be30UL,
    0xd192e819d6ef5218UL, 0xd69906245565a910UL, 0xf40e35855771202aUL, 0x106aa07032bbd1b8UL,
    0x19a4c116b8d2d0c8UL, 0x1e376c085141ab53UL, 0x2748774cdf8eeb99UL, 0x34b0bcb5e19b48a8UL,
    0x391c0cb3c5c95a63UL, 0x4ed8aa4ae3418acbUL, 0x5b9cca4f7763e373UL, 0x682e6ff3d6b2b8a3UL,
    0x748f82ee5defb2fcUL, 0x78a5636f43172f60UL, 0x84c87814a1f0ab72UL, 0x8cc702081a6439ecUL,
    0x90befffa23631e28UL, 0xa4506cebde82bde9UL, 0xbef9a3f7b2c67915UL, 0xc67178f2e372532bUL,
    0xca273eceea26619cUL, 0xd186b8c721c0c207UL, 0xeada7dd6cde0eb1eUL, 0xf57d4f7fee6ed178UL,
    0x06f067aa72176fbaUL, 0x0a637dc5a2c898a6UL, 0x113f9804bef90daeUL, 0x1b710b35131c471bUL,
    0x28db77f523047d84UL, 0x32caab7b40c72493UL, 0x3c9ebe0a15c9bebcUL, 0x431d67c49c100d4cUL,
    0x4cc5d4becb3e42b6UL, 0x597f299cfc657e2aUL, 0x5fcb6fab3ad6faecUL, 0x6c44198c4a475817UL
};

// SHA-512 initial hash values
constant ulong H0[8] = {
    0x6a09e667f3bcc908UL, 0xbb67ae8584caa73bUL, 0x3c6ef372fe94f82bUL, 0xa54ff53a5f1d36f1UL,
    0x510e527fade682d1UL, 0x9b05688c2b3e6c1fUL, 0x1f83d9abfb41bd6bUL, 0x5be0cd19137e2179UL
};

// Right rotate 64-bit
ulong rotr64(ulong x, int n) {
    return (x >> n) | (x << (64 - n));
}

// SHA-512 functions
ulong ch(ulong x, ulong y, ulong z) {
    return (x & y) ^ (~x & z);
}

ulong maj(ulong x, ulong y, ulong z) {
    return (x & y) ^ (x & z) ^ (y & z);
}

ulong sigma0(ulong x) {
    return rotr64(x, 28) ^ rotr64(x, 34) ^ rotr64(x, 39);
}

ulong sigma1(ulong x) {
    return rotr64(x, 14) ^ rotr64(x, 18) ^ rotr64(x, 41);
}

ulong gamma0(ulong x) {
    return rotr64(x, 1) ^ rotr64(x, 8) ^ (x >> 7);
}

ulong gamma1(ulong x) {
    return rotr64(x, 19) ^ rotr64(x, 61) ^ (x >> 6);
}

// Convert 8 bytes to ulong (big endian)
ulong bytes_to_ulong(thread const uchar* bytes) {
    return ((ulong)bytes[0] << 56) | ((ulong)bytes[1] << 48) | ((ulong)bytes[2] << 40) | ((ulong)bytes[3] << 32) |
           ((ulong)bytes[4] << 24) | ((ulong)bytes[5] << 16) | ((ulong)bytes[6] << 8) | ((ulong)bytes[7]);
}

// Convert ulong to 8 bytes (big endian)
void ulong_to_bytes(ulong val, thread uchar* bytes) {
    bytes[0] = (uchar)(val >> 56);
    bytes[1] = (uchar)(val >> 48);
    bytes[2] = (uchar)(val >> 40);
    bytes[3] = (uchar)(val >> 32);
    bytes[4] = (uchar)(val >> 24);
    bytes[5] = (uchar)(val >> 16);
    bytes[6] = (uchar)(val >> 8);
    bytes[7] = (uchar)(val);
}

// SHA-512 hash function
void sha512_hash(thread const uchar* input, int len, thread uchar* output) {
    ulong H[8];
    for (int i = 0; i < 8; i++) {
        H[i] = H0[i];
    }

    ulong W[80];
    uchar padded[1024];
    int padded_len = 0;

    // Copy input
    for (int i = 0; i < len && i < 1000; i++) {
        padded[i] = input[i];
    }
    padded_len = len;

    // Add padding bit
    padded[padded_len] = 0x80;
    padded_len++;

    // Pad to 896 bits mod 1024 (112 bytes mod 128)
    while (padded_len % 128 != 112) {
        padded[padded_len] = 0;
        padded_len++;
    }

    // Add length as 128-bit big-endian
    ulong bit_len = (ulong)len * 8;
    for (int i = 0; i < 8; i++) {
        padded[padded_len + i] = 0;
    }
    for (int i = 0; i < 8; i++) {
        padded[padded_len + 8 + i] = (uchar)(bit_len >> (56 - i * 8));
    }
    padded_len += 16;

    // Process each 1024-bit block
    for (int block = 0; block < padded_len / 128; block++) {
        // Prepare message schedule W
        for (int t = 0; t < 16; t++) {
            uchar temp[8];
            for (int i = 0; i < 8; i++) {
                temp[i] = padded[block * 128 + t * 8 + i];
            }
            W[t] = bytes_to_ulong(temp);
        }

        for (int t = 16; t < 80; t++) {
            W[t] = gamma1(W[t-2]) + W[t-7] + gamma0(W[t-15]) + W[t-16];
        }

        // Initialize working variables
        ulong a = H[0], b = H[1], c = H[2], d = H[3];
        ulong e = H[4], f = H[5], g = H[6], h = H[7];

        // Main loop
        for (int t = 0; t < 80; t++) {
            ulong T1 = h + sigma1(e) + ch(e, f, g) + K[t] + W[t];
            ulong T2 = sigma0(a) + maj(a, b, c);

            h = g;
            g = f;
            f = e;
            e = d + T1;
            d = c;
            c = b;
            b = a;
            a = T1 + T2;
        }

        // Update hash values
        H[0] += a; H[1] += b; H[2] += c; H[3] += d;
        H[4] += e; H[5] += f; H[6] += g; H[7] += h;
    }

    // Convert final hash to bytes
    for (int i = 0; i < 8; i++) {
        ulong_to_bytes(H[i], output + i * 8);
    }
}

// Corrected SHA-512 crypt implementation
void sha512_crypt(device const char* password, int pwd_len, device const char* salt, int salt_len, int rounds, thread uchar* output) {
    uchar digest_a[64], digest_b[64];
    uchar dp[64], ds[64];
    uchar temp_input[2048];
    int temp_len;

    // Step 1: Compute digest B = SHA512(password || salt || password)
    temp_len = 0;
    for (int i = 0; i < pwd_len; i++) {
        temp_input[temp_len++] = (uchar)password[i];
    }
    for (int i = 0; i < salt_len; i++) {
        temp_input[temp_len++] = (uchar)salt[i];
    }
    for (int i = 0; i < pwd_len; i++) {
        temp_input[temp_len++] = (uchar)password[i];
    }
    sha512_hash(temp_input, temp_len, digest_b);

    // Step 2: Start building digest A
    temp_len = 0;

    // A = password || salt
    for (int i = 0; i < pwd_len; i++) {
        temp_input[temp_len++] = (uchar)password[i];
    }
    for (int i = 0; i < salt_len; i++) {
        temp_input[temp_len++] = (uchar)salt[i];
    }

    // Add digest_b for pwd_len bytes
    for (int i = 0; i < pwd_len; i++) {
        temp_input[temp_len++] = digest_b[i % 64];
    }

    // Step 3: For each bit in pwd_len, add alternating content
    for (int i = pwd_len; i > 0; i >>= 1) {
        if (i & 1) {
            // Odd: add entire digest_b (64 bytes)
            for (int j = 0; j < 64; j++) {
                temp_input[temp_len++] = digest_b[j];
            }
        } else {
            // Even: add entire password
            for (int j = 0; j < pwd_len; j++) {
                temp_input[temp_len++] = (uchar)password[j];
            }
        }
    }

    // Compute initial digest_a
    sha512_hash(temp_input, temp_len, digest_a);

    // Step 4: Create DP = SHA512(password repeated pwd_len times)
    temp_len = 0;
    for (int i = 0; i < pwd_len; i++) {
        for (int j = 0; j < pwd_len; j++) {
            if (temp_len < 2000) {
                temp_input[temp_len++] = (uchar)password[j];
            }
        }
    }
    sha512_hash(temp_input, temp_len, dp);

    // Step 5: Create DS = SHA512(salt repeated (16 + digest_a[0]) times)
    temp_len = 0;
    int ds_repeats = 16 + (int)digest_a[0];
    for (int i = 0; i < ds_repeats; i++) {
        for (int j = 0; j < salt_len; j++) {
            if (temp_len < 2000) {
                temp_input[temp_len++] = (uchar)salt[j];
            }
        }
    }
    sha512_hash(temp_input, temp_len, ds);

    // Step 6: Perform rounds iterations (C_i computation)
    for (int round = 0; round < rounds; round++) {
        temp_len = 0;

        // Start with C_{i-1} (digest_a) or DP based on round parity
        if (round & 1) {
            // Odd round: start with DP (password substitute)
            for (int i = 0; i < pwd_len; i++) {
                temp_input[temp_len++] = dp[i];
            }
        } else {
            // Even round: start with digest_a (C_{i-1})
            for (int i = 0; i < 64; i++) {
                temp_input[temp_len++] = digest_a[i];
            }
        }

        // Add salt if round is not divisible by 3
        if (round % 3 != 0) {
            for (int i = 0; i < salt_len; i++) {
                temp_input[temp_len++] = ds[i];
            }
        }

        // Add password if round is not divisible by 7
        if (round % 7 != 0) {
            for (int i = 0; i < pwd_len; i++) {
                temp_input[temp_len++] = dp[i];
            }
        }

        // End with C_{i-1} (digest_a) or DP based on round parity (opposite of start)
        if (round & 1) {
            // Odd round: end with digest_a (C_{i-1})
            for (int i = 0; i < 64; i++) {
                temp_input[temp_len++] = digest_a[i];
            }
        } else {
            // Even round: end with DP (password substitute)
            for (int i = 0; i < pwd_len; i++) {
                temp_input[temp_len++] = dp[i];
            }
        }

        // Compute C_i = SHA512(constructed_input)
        sha512_hash(temp_input, temp_len, digest_a);
    }

    // Copy final digest to output
    for (int i = 0; i < 64; i++) {
        output[i] = digest_a[i];
    }
}

// Crypt base64 alphabet (custom ordering)
constant char crypt64_alphabet[64] = {
    '.', '/', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
    'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z'
};

// Convert SHA-512 crypt digest to base64 string with specific byte ordering
void crypt_encode_sha512(thread const uchar* digest, thread char* output) {
    // SHA-512 crypt uses specific byte reordering
    int indices[21][3] = {
        {0, 21, 42}, {22, 43, 1}, {44, 2, 23}, {3, 24, 45}, {25, 46, 4}, {47, 5, 26}, {6, 27, 48},
        {28, 49, 7}, {50, 8, 29}, {9, 30, 51}, {31, 52, 10}, {53, 11, 32}, {12, 33, 54}, {34, 55, 13},
        {56, 14, 35}, {15, 36, 57}, {37, 58, 16}, {59, 17, 38}, {18, 39, 60}, {40, 61, 19}, {62, 20, 41}
    };

    int out_pos = 0;

    // Process 21 groups of 3 bytes each
    for (int group = 0; group < 21; group++) {
        ulong val = 0;
        val |= ((ulong)digest[indices[group][0]]) << 16;
        val |= ((ulong)digest[indices[group][1]]) << 8;
        val |= ((ulong)digest[indices[group][2]]);

        // Convert to 4 base64 characters
        output[out_pos++] = crypt64_alphabet[val & 0x3f];
        val >>= 6;
        output[out_pos++] = crypt64_alphabet[val & 0x3f];
        val >>= 6;
        output[out_pos++] = crypt64_alphabet[val & 0x3f];
        val >>= 6;
        output[out_pos++] = crypt64_alphabet[val & 0x3f];
    }

    // Handle remaining byte (index 63)
    ulong val = digest[63];
    output[out_pos++] = crypt64_alphabet[val & 0x3f];
    val >>= 6;
    output[out_pos++] = crypt64_alphabet[val & 0x3f];

    output[out_pos] = '\0';
}

// String length function
int strlen(device const char* str) {
    int len = 0;
    while (str[len] != '\0' && len < 31) { // Max salt length
        len++;
    }
    return len;
}

// String comparison
bool str_equal(thread const char* a, device const char* b, int len) {
    for (int i = 0; i < len; i++) {
        if (a[i] != b[i]) return false;
        if (a[i] == '\0') return true;
    }
    return true;
}

kernel void crack_passwords(
    device const GpuPassword* passwords [[buffer(0)]],
    device const GpuTarget* target [[buffer(1)]],
    device GpuResult* result [[buffer(2)]],
    constant uint& num_passwords [[buffer(3)]],
    uint gid [[thread_position_in_grid]]
) {
    if (gid >= num_passwords) return;

    // Early exit if password already found
    if (atomic_load_explicit(&result->found, memory_order_relaxed)) return;

    const device GpuPassword& pwd = passwords[gid];

    // Compute SHA-512 crypt hash for this password
    uchar computed_hash[64];
    sha512_crypt(pwd.password, pwd.password_len, target->salt,
                strlen(target->salt), target->rounds, computed_hash);

    // Encode the computed hash using crypt base64 encoding
    char encoded_hash[87]; // 86 chars + null terminator
    crypt_encode_sha512(computed_hash, encoded_hash);

    // Compare with target hash
    bool match = str_equal(encoded_hash, target->hash, 86);

    if (match) {
        int expected = 0;
        if (atomic_compare_exchange_weak_explicit(&result->found, &expected, 1,
                                                memory_order_relaxed, memory_order_relaxed)) {
            result->index = gid;
            for (int i = 0; i < pwd.password_len && i < 63; i++) {
                result->password[i] = pwd.password[i];
            }
            result->password[pwd.password_len] = '\0';
        }
    }
}
"#;

pub fn crack_password_gpu(
    target: &HashTarget,
    wordlist: &[String],
    progress: Arc<ProgressBar>,
    found: Arc<AtomicBool>,
    attempts: Arc<AtomicU64>,
) -> Result<Option<String>> {
    // Initialize Metal (only once at the start)
    let device = Device::system_default().ok_or_else(|| anyhow!("No Metal device available"))?;
    let command_queue = device.new_command_queue();

    // Print initialization info only once
    if attempts.load(Ordering::Relaxed) == 0 {
        println!("🚀 Starting Metal GPU acceleration...");
        println!("Device: {}", device.name());
    }

    // Compile shader
    let library = device.new_library_with_source(SHA512_CRYPT_SHADER, &CompileOptions::new())
        .map_err(|e| anyhow!("Failed to compile Metal shader: {}", e))?;
    let kernel = library.get_function("crack_passwords", None)
        .map_err(|e| anyhow!("Failed to get kernel function: {}", e))?;

    // Create compute pipeline state
    let pipeline_state = device.new_compute_pipeline_state_with_function(&kernel)
        .map_err(|e| anyhow!("Failed to create pipeline state: {}", e))?;

    // Use smaller batch sizes to avoid GPU timeout
    let batch_size = 2048.min(wordlist.len());

    // Print batch size only once
    if attempts.load(Ordering::Relaxed) == 0 {
        println!("Batch size: {}", batch_size);
    }

    // Process wordlist in batches
    for chunk in wordlist.chunks(batch_size) {
        if found.load(Ordering::Relaxed) {
            break;
        }

        // Prepare password batch
        let mut gpu_passwords = Vec::with_capacity(batch_size);
        for password in chunk {
            let mut gpu_pwd = GpuPassword::default();
            let bytes = password.as_bytes();
            let len = bytes.len().min(63); // Max password length - 1 for null terminator
            gpu_pwd.password[..len].copy_from_slice(&bytes[..len]);
            gpu_pwd.password_len = len as i32;
            gpu_passwords.push(gpu_pwd);
        }

        // Create Metal buffers
        let passwords_buffer = device.new_buffer_with_data(
            gpu_passwords.as_ptr() as *const _,
            (gpu_passwords.len() * std::mem::size_of::<GpuPassword>()) as u64,
            MTLResourceOptions::StorageModeShared,
        );

        let gpu_target = GpuTarget::from_hash_target(target)?;
        let target_buffer = device.new_buffer_with_data(
            &gpu_target as *const _ as *const _,
            std::mem::size_of::<GpuTarget>() as u64,
            MTLResourceOptions::StorageModeShared,
        );

        let gpu_result = GpuResult::default();
        let result_buffer = device.new_buffer_with_data(
            &gpu_result as *const _ as *const _,
            std::mem::size_of::<GpuResult>() as u64,
            MTLResourceOptions::StorageModeShared,
        );

        // Create command buffer and encoder
        let command_buffer = command_queue.new_command_buffer();
        let encoder = command_buffer.new_compute_command_encoder();

        // Set up compute command
        encoder.set_compute_pipeline_state(&pipeline_state);
        encoder.set_buffer(0, Some(&passwords_buffer), 0);
        encoder.set_buffer(1, Some(&target_buffer), 0);
        encoder.set_buffer(2, Some(&result_buffer), 0);

        let num_passwords = gpu_passwords.len() as u32;
        encoder.set_bytes(3, std::mem::size_of::<u32>() as u64, &num_passwords as *const _ as *const _);

        // Dispatch threads
        let threads_per_threadgroup = MTLSize::new(64, 1, 1);
        let threadgroups = MTLSize::new(
            (num_passwords as u64 + 63) / 64,
            1,
            1,
        );

        encoder.dispatch_thread_groups(threadgroups, threads_per_threadgroup);
        encoder.end_encoding();

        // Execute
        command_buffer.commit();
        command_buffer.wait_until_completed();

        // Read result
        let result_ptr = result_buffer.contents() as *const GpuResult;
        let gpu_result = unsafe { *result_ptr };

        // Update progress (this will update the existing progress bar)
        attempts.fetch_add(chunk.len() as u64, Ordering::Relaxed);
        progress.inc(chunk.len() as u64);

        // Check if GPU found a password
        if gpu_result.found != 0 {
            let password_bytes = &gpu_result.password;
            let password_len = gpu_result.index.min(63) as usize;

            // Find the null terminator
            let end = password_bytes.iter().position(|&x| x == 0).unwrap_or(password_len);
            let password = String::from_utf8_lossy(&password_bytes[..end]).to_string();

            found.store(true, Ordering::Relaxed);
            progress.set_message(format!("Found: {}", password));
            return Ok(Some(password));
        }
    }

    Ok(None)
}

#[repr(C)]
#[derive(Debug, Clone)]
struct GpuPassword {
    password: [u8; 64],
    password_len: i32,
}

impl Default for GpuPassword {
    fn default() -> Self {
        Self {
            password: [0; 64],
            password_len: 0,
        }
    }
}

#[repr(C)]
#[derive(Debug, Clone)]
struct GpuTarget {
    hash: [u8; 129], // 128 hex chars + null terminator
    salt: [u8; 32],
    rounds: i32,
}

impl Default for GpuTarget {
    fn default() -> Self {
        Self {
            hash: [0; 129],
            salt: [0; 32],
            rounds: 0,
        }
    }
}

impl GpuTarget {
    fn from_hash_target(target: &HashTarget) -> Result<Self> {
        let mut gpu_target = Self::default();

        // Extract hash part (after the $6$salt$)
        let hash_part = target.hash.split('$').nth(3)
            .ok_or_else(|| anyhow!("Invalid hash format"))?;

        let hash_bytes = hash_part.as_bytes();
        let len = hash_bytes.len().min(128);
        gpu_target.hash[..len].copy_from_slice(&hash_bytes[..len]);

        let salt_bytes = target.salt.as_bytes();
        let salt_len = salt_bytes.len().min(31);
        gpu_target.salt[..salt_len].copy_from_slice(&salt_bytes[..salt_len]);

        gpu_target.rounds = target.rounds as i32;
        
        Ok(gpu_target)
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct GpuResult {
    found: i32,  // This will be treated as atomic_int on the GPU side
    index: i32,
    password: [u8; 64],
}

impl Default for GpuResult {
    fn default() -> Self {
        Self {
            found: 0,
            index: 0,
            password: [0; 64],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_gpu_target_creation() {
        let target = HashTarget {
            username: "test".to_string(),
            hash: "$6$testsalt$hashvalue123".to_string(),
            salt: "testsalt".to_string(),
            rounds: 5000,
        };
        
        let gpu_target = GpuTarget::from_hash_target(&target).unwrap();
        assert_eq!(gpu_target.rounds, 5000);
        
        let salt_str = String::from_utf8_lossy(&gpu_target.salt);
        assert!(salt_str.starts_with("testsalt"));
    }
}
