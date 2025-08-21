use crate::HashTarget;
use anyhow::{anyhow, Result};
use indicatif::ProgressBar;
use opencl3::command_queue::{CommandQueue, CL_QUEUE_PROFILING_ENABLE};
use opencl3::context::Context;
use opencl3::device::{get_all_devices, Device, CL_DEVICE_TYPE_GPU};
use opencl3::kernel::{ExecuteKernel, Kernel};
use opencl3::memory::{Buffer, CL_MEM_READ_ONLY, CL_MEM_WRITE_ONLY};
use opencl3::types::CL_TRUE;
use opencl3::platform::get_platforms;
use opencl3::program::Program;
use std::ptr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

const SHA512_CRYPT_KERNEL: &str = r#"
// OpenCL kernel for SHA512 crypt password hashing
// This is a simplified version - full implementation would require
// complete SHA512 crypt algorithm including rounds and salt handling

#define HASH_SIZE 64
#define MAX_PASSWORD_LENGTH 64
#define MAX_SALT_LENGTH 32

typedef struct {
    char password[MAX_PASSWORD_LENGTH];
    int password_len;
} password_t;

typedef struct {
    char hash[HASH_SIZE * 2 + 1]; // Hex representation + null terminator
    char salt[MAX_SALT_LENGTH];
    int rounds;
} target_t;

typedef struct {
    int found;
    int index;
    char password[MAX_PASSWORD_LENGTH];
} result_t;

// Simplified SHA512 implementation for demonstration
// In production, you'd want a complete, optimized implementation
void sha512_simple(const char* input, int len, unsigned char* output) {
    // This is a placeholder - real implementation would do proper SHA512
    // For now, we'll just do a simple hash for demonstration
    for (int i = 0; i < 64; i++) {
        output[i] = (unsigned char)(i + len) % 256;
    }
}

// Convert bytes to hex string
void bytes_to_hex(const unsigned char* bytes, int len, char* hex) {
    const char hex_chars[] = "0123456789abcdef";
    for (int i = 0; i < len; i++) {
        hex[i * 2] = hex_chars[(bytes[i] >> 4) & 0xF];
        hex[i * 2 + 1] = hex_chars[bytes[i] & 0xF];
    }
    hex[len * 2] = '\0';
}

// String comparison
int str_equal(const char* a, const char* b, int len) {
    for (int i = 0; i < len; i++) {
        if (a[i] != b[i]) return 0;
        if (a[i] == '\0') return 1;
    }
    return 1;
}

__kernel void crack_passwords(
    __global const password_t* passwords,
    __global const target_t* target,
    __global result_t* result,
    const int num_passwords
) {
    int gid = get_global_id(0);
    
    if (gid >= num_passwords) return;
    
    // Early exit if password already found
    if (atomic_load(&result->found)) return;
    
    const password_t* pwd = &passwords[gid];
    unsigned char hash_bytes[64];
    char hash_hex[129];
    
    // Hash the password (simplified)
    sha512_simple(pwd->password, pwd->password_len, hash_bytes);
    bytes_to_hex(hash_bytes, 64, hash_hex);
    
    // Compare with target hash
    if (str_equal(hash_hex, target->hash, 128)) {
        // Password found!
        if (atomic_compare_exchange_strong(&result->found, 0, 1)) {
            result->index = gid;
            for (int i = 0; i < pwd->password_len && i < MAX_PASSWORD_LENGTH - 1; i++) {
                result->password[i] = pwd->password[i];
            }
            result->password[pwd->password_len] = '\0';
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
) -> Result<String> {
    // Initialize OpenCL
    let platforms = get_platforms()?;
    if platforms.is_empty() {
        return Err(anyhow!("No OpenCL platforms found"));
    }
    
    let _platform = platforms[0];
    let devices = get_all_devices(CL_DEVICE_TYPE_GPU)?;
    if devices.is_empty() {
        return Err(anyhow!("No GPU devices found"));
    }
    
    let device = Device::new(devices[0]);
    let context = Context::from_device(&device)?;
    let queue = CommandQueue::create_default_with_properties(
        &context,
        CL_QUEUE_PROFILING_ENABLE,
        0,
    )?;
    
    // Build OpenCL program
    let program = Program::create_and_build_from_source(&context, SHA512_CRYPT_KERNEL, "")
        .map_err(|e| anyhow!("Failed to build OpenCL program: {}", e))?;
    let kernel = Kernel::create(&program, "crack_passwords")?;
    
    // Prepare data structures
    let batch_size = 8192.min(wordlist.len()); // Process in batches
    let mut gpu_passwords = Vec::with_capacity(batch_size);
    
    println!("🚀 Starting GPU acceleration...");
    println!("Device: {}", device.name()?);
    println!("Batch size: {}", batch_size);
    
    // Process wordlist in batches
    for chunk in wordlist.chunks(batch_size) {
        if found.load(Ordering::Relaxed) {
            break;
        }
        
        // Prepare password batch
        gpu_passwords.clear();
        for password in chunk {
            let mut gpu_pwd = GpuPassword::default();
            let bytes = password.as_bytes();
            let len = bytes.len().min(63); // Max password length - 1 for null terminator
            gpu_pwd.password[..len].copy_from_slice(&bytes[..len]);
            gpu_pwd.password_len = len as i32;
            gpu_passwords.push(gpu_pwd);
        }
        
        // Create buffers
        let (passwords_buffer, target_buffer, result_buffer) = unsafe {
            let passwords_buffer = Buffer::create(
                &context,
                CL_MEM_READ_ONLY,
                gpu_passwords.len() * std::mem::size_of::<GpuPassword>(),
                ptr::null_mut(),
            )?;
            
            let target_buffer = Buffer::create(
                &context,
                CL_MEM_READ_ONLY,
                std::mem::size_of::<GpuTarget>(),
                ptr::null_mut(),
            )?;
            
            let result_buffer = Buffer::create(
                &context,
                CL_MEM_WRITE_ONLY,
                std::mem::size_of::<GpuResult>(),
                ptr::null_mut(),
            )?;
            
            (passwords_buffer, target_buffer, result_buffer)
        };
        
        // Prepare target data
        let gpu_target = GpuTarget::from_hash_target(target)?;
        
        // Write data to GPU
        let mut passwords_buffer_mut = passwords_buffer;
        let mut target_buffer_mut = target_buffer;
        let mut result_buffer_mut = result_buffer;
        
        unsafe {
            queue.enqueue_write_buffer(&mut passwords_buffer_mut, CL_TRUE, 0, &gpu_passwords, &[])?;
            queue.enqueue_write_buffer(&mut target_buffer_mut, CL_TRUE, 0, &[gpu_target], &[])?;
        }
        
        // Initialize result
        let gpu_result_for_write = GpuResult::default();
        unsafe {
            queue.enqueue_write_buffer(&mut result_buffer_mut, CL_TRUE, 0, &[gpu_result_for_write], &[])?;
        }
        
        // Execute kernel
        let kernel_event = unsafe {
            ExecuteKernel::new(&kernel)
                .set_arg(&passwords_buffer_mut)
                .set_arg(&target_buffer_mut)
                .set_arg(&result_buffer_mut)
                .set_arg(&(gpu_passwords.len() as i32))
                .set_global_work_size(gpu_passwords.len())
                .enqueue_nd_range(&queue)?
        };
        
        // Wait for completion
        kernel_event.wait()?;
        
        // Read result
        let mut gpu_result = GpuResult::default();
        unsafe {
            queue.enqueue_read_buffer(&result_buffer_mut, CL_TRUE, 0, std::slice::from_mut(&mut gpu_result), &[])?;
        }
        
        // Update progress
        attempts.fetch_add(chunk.len() as u64, Ordering::Relaxed);
        progress.inc(chunk.len() as u64);
        
        // Check if password found
        if gpu_result.found != 0 {
            let password = String::from_utf8_lossy(&gpu_result.password)
                .trim_end_matches('\0')
                .to_string();
            found.store(true, Ordering::Relaxed);
            progress.set_message(format!("Found: {}", password));
            return Ok(password);
        }
    }
    
    Err(anyhow!("Password not found in wordlist"))
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
#[derive(Debug, Clone)]
struct GpuResult {
    found: i32,
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
