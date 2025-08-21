
use anyhow::{anyhow, Result};
use clap::Parser;
use indicatif::{ProgressBar, ProgressStyle};
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

mod gpu_cracker_metal;
use gpu_cracker_metal as gpu_cracker;
mod cpu_cracker;
mod wordlist;
mod progress;
mod mask;

#[derive(Parser)]
#[command(name = "gpu_password_cracker")]
#[command(about = "A GPU-accelerated password recovery tool")]
struct Cli {
    /// Path to shadow file or hash string
    #[arg(short = 'H', long)]
    hash: String,

    /// Path to wordlist file
    #[arg(short, long)]
    wordlist: Option<PathBuf>,

    /// Mask pattern for brute force (e.g., ?d?d?d?d for 4 digits)
    #[arg(short, long)]
    mask: Option<String>,

    /// Use GPU acceleration (requires Metal on macOS)
    #[arg(short, long)]
    gpu: bool,

    /// Number of CPU threads (default: all cores)
    #[arg(short, long)]
    threads: Option<usize>,

    /// Progress file for resuming
    #[arg(short, long)]
    progress_file: Option<PathBuf>,

    /// Username to crack (if hash file contains multiple users)
    #[arg(short, long)]
    username: Option<String>,

    /// Custom digit range (e.g., "0-4" for digits 0,1,2,3,4)
    #[arg(long)]
    digit_range: Option<String>,

    /// Custom character range (e.g., "a-z" or "!@#$%^&*")
    #[arg(long)]
    character_range: Option<String>,
}

#[derive(Debug, Clone)]
pub struct HashTarget {
    pub username: String,
    pub hash: String,
    pub salt: String,
    pub rounds: u32,
}

fn main() -> Result<()> {
    let args = Cli::parse();

    // Validate arguments
    let mode_count = [args.wordlist.is_some(), args.mask.is_some()].iter().filter(|&&x| x).count();
    if mode_count == 0 {
        return Err(anyhow!("Must specify either --wordlist or --mask"));
    }
    if mode_count > 1 {
        return Err(anyhow!("Cannot specify multiple modes: choose only one of --wordlist or --mask"));
    }

    // Parse the hash target
    let target = parse_hash_input(&args.hash, &args.username)?;

    println!("🔓 GPU Password Cracker v0.1.0");
    println!("Target user: {}", target.username);
    println!("Hash algorithm: SHA512 crypt");
    println!("Rounds: {}", target.rounds);
    println!("Using GPU: {}", args.gpu);

    // Generate password candidates
    let (wordlist, total_combinations) = if let Some(wordlist_path) = &args.wordlist {
        // Wordlist mode
        let wordlist = wordlist::load_wordlist(wordlist_path)?;
        let total = wordlist.len();
        println!("Loaded {} passwords from wordlist", total);
        (wordlist, total as u64)
    } else if let Some(mask_pattern) = &args.mask {
        // Mask mode
        let pattern = if args.digit_range.is_some() || args.character_range.is_some() {
            mask::MaskPattern::from_mask_with_ranges(
                mask_pattern,
                args.digit_range.as_deref(),
                args.character_range.as_deref()
            )?
        } else {
            mask::MaskPattern::from_mask(mask_pattern)?
        };
        println!("Mask pattern: {}", mask_pattern);
        if let Some(digit_range) = &args.digit_range {
            println!("Custom digit range: {}", digit_range);
        }
        if let Some(character_range) = &args.character_range {
            println!("Custom character range: {}", character_range);
        }
        println!("Total combinations: {}", pattern.total_combinations);

        if pattern.total_combinations > 1_000_000 {
            println!("⚠️  Large mask pattern detected. Using batch processing...");
            return run_mask_attack_batched(&target, pattern, &args);
        } else {
            let wordlist = pattern.generate_all_passwords()?;
            println!("Generated {} password candidates", wordlist.len());
            (wordlist, pattern.total_combinations)
        }
    } else {
        unreachable!("Should have been caught by argument validation");
    };
    
    // Set up progress tracking
    let progress = Arc::new(ProgressBar::new(total_combinations));
    progress.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {pos}/{len} ({eta})")
            .unwrap()
            .progress_chars("#>-"),
    );
    
    let found = Arc::new(AtomicBool::new(false));
    let attempts = Arc::new(AtomicU64::new(0));
    
    let start_time = Instant::now();
    
    let result = if args.gpu {
        // Try GPU acceleration first
        match gpu_cracker::crack_password_gpu(&target, &wordlist, progress.clone(), found.clone(), attempts.clone()) {
            Ok(password_option) => password_option,
            Err(e) => {
                println!("⚠️  GPU acceleration failed: {}", e);
                println!("🔄 Falling back to CPU...");
                cpu_cracker::crack_password_cpu(&target, &wordlist, args.threads, progress.clone(), found.clone(), attempts.clone())?
            }
        }
    } else {
        // Use CPU-only cracking
        cpu_cracker::crack_password_cpu(&target, &wordlist, args.threads, progress.clone(), found.clone(), attempts.clone())?
    };
    
    progress.finish();
    
    let duration = start_time.elapsed();
    let total_attempts = attempts.load(Ordering::Relaxed);
    let rate = total_attempts as f64 / duration.as_secs_f64();
    
    match result {
        Some(password) => {
            println!("\n🎉 PASSWORD FOUND!");
            println!("User: {}", target.username);
            println!("Password: {}", password);
            println!("Time taken: {:.2}s", duration.as_secs_f64());
            println!("Attempts: {}", total_attempts);
            println!("Rate: {:.0} attempts/sec", rate);
        }
        None => {
            if args.mask.is_some() {
                println!("\n❌ Password not found using mask pattern");
            } else {
                println!("\n❌ Password not found in wordlist");
            }
            println!("Time taken: {:.2}s", duration.as_secs_f64());
            println!("Total attempts: {}", total_attempts);
            println!("Rate: {:.0} attempts/sec", rate);
        }
    }
    
    Ok(())
}

/// Handle large mask patterns with batch processing
fn run_mask_attack_batched(target: &HashTarget, pattern: mask::MaskPattern, args: &Cli) -> Result<()> {
    const BATCH_SIZE: u64 = 100_000; // Process 100k passwords at a time
    
    let progress = Arc::new(ProgressBar::new(pattern.total_combinations));
    progress.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {pos}/{len} ({eta}) - {msg}")
            .unwrap()
            .progress_chars("#>-"),
    );
    
    let found = Arc::new(AtomicBool::new(false));
    let attempts = Arc::new(AtomicU64::new(0));
    let start_time = Instant::now();
    
    let mut current_index = 0u64;
    while current_index < pattern.total_combinations && !found.load(Ordering::Relaxed) {
        let batch_size = BATCH_SIZE.min(pattern.total_combinations - current_index);

        // Set progress message for batch generation
        progress.set_message(format!("Generating batch {}-{}", current_index, current_index + batch_size - 1));

        let batch = pattern.generate_batch(current_index, batch_size)?;

        // Set progress message for processing
        progress.set_message(format!("Processing {} passwords", batch.len()));

        let result = if args.gpu {
            // Try GPU acceleration first
            match gpu_cracker::crack_password_gpu(target, &batch, progress.clone(), found.clone(), attempts.clone()) {
                Ok(Some(password)) => {
                    progress.finish_with_message(format!("Password found: {}", password));
                    println!("\n🎉 PASSWORD FOUND!");
                    println!("User: {}", target.username);
                    println!("Password: {}", password);
                    let duration = start_time.elapsed();
                    let total_attempts = attempts.load(Ordering::Relaxed);
                    let rate = total_attempts as f64 / duration.as_secs_f64();
                    println!("Time taken: {:.2}s", duration.as_secs_f64());
                    println!("Attempts: {}", total_attempts);
                    println!("Rate: {:.0} attempts/sec", rate);
                    return Ok(());
                }
                Ok(None) => {
                    // GPU completed successfully but didn't find password, continue to next batch
                }
                Err(e) => {
                    println!("⚠️  GPU acceleration failed: {}", e);
                    println!("🔄 Falling back to CPU...");
                    progress.set_message("Using CPU fallback");
                    if let Some(password) = cpu_cracker::crack_password_cpu(target, &batch, args.threads, progress.clone(), found.clone(), attempts.clone())? {
                        progress.finish_with_message(format!("Password found: {}", password));
                        println!("\n🎉 PASSWORD FOUND!");
                        println!("User: {}", target.username);
                        println!("Password: {}", password);
                        let duration = start_time.elapsed();
                        let total_attempts = attempts.load(Ordering::Relaxed);
                        let rate = total_attempts as f64 / duration.as_secs_f64();
                        println!("Time taken: {:.2}s", duration.as_secs_f64());
                        println!("Attempts: {}", total_attempts);
                        println!("Rate: {:.0} attempts/sec", rate);
                        return Ok(());
                    }
                }
            }
        } else {
            // Use CPU-only cracking
            progress.set_message("Using CPU processing");
            if let Some(password) = cpu_cracker::crack_password_cpu(target, &batch, args.threads, progress.clone(), found.clone(), attempts.clone())? {
                progress.finish_with_message(format!("Password found: {}", password));
                println!("\n🎉 PASSWORD FOUND!");
                println!("User: {}", target.username);
                println!("Password: {}", password);
                let duration = start_time.elapsed();
                let total_attempts = attempts.load(Ordering::Relaxed);
                let rate = total_attempts as f64 / duration.as_secs_f64();
                println!("Time taken: {:.2}s", duration.as_secs_f64());
                println!("Attempts: {}", total_attempts);
                println!("Rate: {:.0} attempts/sec", rate);
                return Ok(());
            }
        };
        
        current_index += batch_size;
    }
    
    progress.finish();
    let duration = start_time.elapsed();
    let total_attempts = attempts.load(Ordering::Relaxed);
    let rate = total_attempts as f64 / duration.as_secs_f64();
    
    println!("\n❌ Password not found using mask pattern");
    println!("Time taken: {:.2}s", duration.as_secs_f64());
    println!("Total attempts: {}", total_attempts);
    println!("Rate: {:.0} attempts/sec", rate);
    
    Ok(())
}

fn parse_hash_input(input: &str, username_filter: &Option<String>) -> Result<HashTarget> {
    if input.starts_with('$') {
        // Direct hash input
        parse_sha512_hash("unknown", input)
    } else {
        // File input
        let content = fs::read_to_string(input)
            .map_err(|e| anyhow!("Failed to read hash file: {}", e))?;
        
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            
            let parts: Vec<&str> = line.split(':').collect();
            if parts.len() >= 2 {
                let username = parts[0];
                let hash = parts[1];
                
                // Filter by username if specified
                if let Some(target_user) = username_filter {
                    if username != target_user {
                        continue;
                    }
                }
                
                // Only process SHA512 hashes
                if hash.starts_with("$6$") {
                    return parse_sha512_hash(username, hash);
                }
            }
        }
        
        Err(anyhow!("No suitable SHA512 hash found in file"))
    }
}

fn parse_sha512_hash(username: &str, hash: &str) -> Result<HashTarget> {
    if !hash.starts_with("$6$") {
        return Err(anyhow!("Not a SHA512 crypt hash"));
    }
    
    let parts: Vec<&str> = hash.splitn(4, '$').collect();
    if parts.len() != 4 {
        return Err(anyhow!("Invalid SHA512 crypt hash format"));
    }
    
    // Parse rounds if present
    let (salt, rounds) = if parts[2].starts_with("rounds=") {
        let round_salt: Vec<&str> = parts[2].splitn(2, '$').collect();
        if round_salt.len() != 2 {
            return Err(anyhow!("Invalid rounds format"));
        }
        
        let rounds_str = round_salt[0].strip_prefix("rounds=")
            .ok_or_else(|| anyhow!("Invalid rounds prefix"))?;
        let rounds = rounds_str.parse::<u32>()
            .map_err(|_| anyhow!("Invalid rounds number"))?;
        
        (round_salt[1].to_string(), rounds)
    } else {
        (parts[2].to_string(), 5000) // Default rounds
    };
    
    Ok(HashTarget {
        username: username.to_string(),
        hash: hash.to_string(),
        salt,
        rounds,
    })
}
