
use indicatif::ProgressBar;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use anyhow::Result;
use crate::HashTarget;
use std::sync::Arc;
use std::sync::Once;

static THREAD_POOL_INIT: Once = Once::new();

pub fn crack_password_cpu(
    target: &HashTarget,
    wordlist: &[String],
    threads: Option<usize>,
    progress: Arc<ProgressBar>,
    found: Arc<AtomicBool>,
    attempts: Arc<AtomicU64>,
) -> Result<Option<String>> {
    // Configure thread pool only once
    if let Some(thread_count) = threads {
        THREAD_POOL_INIT.call_once(|| {
            if let Err(e) = rayon::ThreadPoolBuilder::new()
                .num_threads(thread_count)
                .build_global()
            {
                eprintln!("Warning: Failed to configure thread pool: {}", e);
            }
        });
    }

    let target_hash = target.hash.clone();
    let result = Arc::new(std::sync::Mutex::new(None::<String>));

    use rayon::prelude::*;

    wordlist.par_iter().find_any(|&password| {
        // Early exit if password already found
        if found.load(Ordering::Relaxed) {
            return false;
        }

        // Increment attempt counter
        attempts.fetch_add(1, Ordering::Relaxed);
        progress.inc(1);

        // Check password
        let matches = sha_crypt::sha512_check(password, &target_hash).is_ok();

        if matches {
            found.store(true, Ordering::Relaxed);
            *result.lock().unwrap() = Some(password.clone());
            progress.set_message(format!("Found: {}", password));
            return true;
        }

        false
    });

    let final_result = result.lock().unwrap().clone();
    Ok(final_result)
}

/// Verify a password against a hash target (for testing)
pub fn verify_password(target: &HashTarget, password: &str) -> bool {
    sha_crypt::sha512_check(password, &target.hash).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::HashTarget;
    use sha_crypt::sha512_simple;
    
    #[test]
    fn test_verify_password() {
        let test_password = "testpassword123";
        let params = sha_crypt::Sha512Params::new(5000).unwrap();
        let hash = sha512_simple(test_password, &params).unwrap();
        
        let target = HashTarget {
            username: "test".to_string(),
            hash: hash.clone(),
            salt: "testsalt".to_string(),
            rounds: 5000,
        };
        
        assert!(verify_password(&target, test_password));
        assert!(!verify_password(&target, "wrongpassword"));
    }
    
    #[test]
    fn test_crack_password_cpu() {
        let test_password = "findme";
        let params = sha_crypt::Sha512Params::new(5000).unwrap();
        let hash = sha512_simple(test_password, &params).unwrap();
        
        let target = HashTarget {
            username: "test".to_string(),
            hash: hash.clone(),
            salt: "testsalt".to_string(),
            rounds: 5000,
        };
        
        let wordlist = vec![
            "password".to_string(),
            "admin".to_string(),
            "findme".to_string(),
            "root".to_string(),
        ];
        
        let progress = Arc::new(ProgressBar::new(wordlist.len() as u64));
        let found = Arc::new(AtomicBool::new(false));
        let attempts = Arc::new(AtomicU64::new(0));
        
        let result = crack_password_cpu(&target, &wordlist, Some(1), progress, found, attempts).unwrap();
        
        assert_eq!(result, Some("findme".to_string()));
    }
}
