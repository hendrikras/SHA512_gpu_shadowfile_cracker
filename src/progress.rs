use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ProgressState {
    pub target_hash: String,
    pub wordlist_path: String,
    pub current_position: usize,
    pub total_attempts: u64,
    pub start_time: u64,
    pub last_update: u64,
    pub found_password: Option<String>,
    pub total_combinations: ()
}

impl ProgressState {
    pub fn new(target_hash: String, wordlist_path: String, _total_size: usize) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        Self {
            target_hash,
            wordlist_path,
            current_position: 0,
            total_attempts: 0,
            start_time: now,
            last_update: now,
            found_password: None,
            total_combinations: (),
        }
    }
    
    pub fn update_position(&mut self, position: usize, attempts: u64) {
        self.current_position = position;
        self.total_attempts = attempts;
        self.last_update = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
    }
    
    pub fn mark_found(&mut self, password: String) {
        self.found_password = Some(password);
        self.last_update = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
    }
    
    pub fn elapsed_time(&self) -> u64 {
        self.last_update - self.start_time
    }
    
    pub fn attempts_per_second(&self) -> f64 {
        if self.elapsed_time() == 0 {
            0.0
        } else {
            self.total_attempts as f64 / self.elapsed_time() as f64
        }
    }
}

pub fn save_progress(progress: &ProgressState, file_path: &PathBuf) -> Result<()> {
    let json = serde_json::to_string_pretty(progress)
        .map_err(|e| anyhow!("Failed to serialize progress: {}", e))?;
    
    fs::write(file_path, json)
        .map_err(|e| anyhow!("Failed to write progress file '{}': {}", file_path.display(), e))?;
    
    Ok(())
}

pub fn load_progress(file_path: &PathBuf) -> Result<ProgressState> {
    if !file_path.exists() {
        return Err(anyhow!("Progress file '{}' does not exist", file_path.display()));
    }
    
    let content = fs::read_to_string(file_path)
        .map_err(|e| anyhow!("Failed to read progress file '{}': {}", file_path.display(), e))?;
    
    let progress: ProgressState = serde_json::from_str(&content)
        .map_err(|e| anyhow!("Failed to parse progress file: {}", e))?;
    
    Ok(progress)
}

/// Auto-saving progress tracker that periodically saves state
pub struct AutoSaveProgress {
    state: ProgressState,
    file_path: Option<PathBuf>,
    save_interval: u64, // seconds
    last_save: u64,
}

impl AutoSaveProgress {
    pub fn new(state: ProgressState, file_path: Option<PathBuf>) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        Self {
            state,
            file_path,
            save_interval: 30, // Save every 30 seconds
            last_save: now,
        }
    }
    
    pub fn update(&mut self, position: usize, attempts: u64) -> Result<()> {
        self.state.update_position(position, attempts);
        
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        // Auto-save if enough time has passed
        if now - self.last_save >= self.save_interval {
            self.save()?;
            self.last_save = now;
        }
        
        Ok(())
    }
    
    pub fn mark_found(&mut self, password: String) -> Result<()> {
        self.state.mark_found(password);
        self.save() // Always save when password is found
    }
    
    pub fn save(&self) -> Result<()> {
        if let Some(path) = &self.file_path {
            save_progress(&self.state, path)?;
        }
        Ok(())
    }
    
    pub fn state(&self) -> &ProgressState {
        &self.state
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;
    
    #[test]
    fn test_progress_state() {
        let mut progress = ProgressState::new(
            "$6$testsalt$hash".to_string(),
            "/path/to/wordlist.txt".to_string(),
            1000,
        );
        
        assert_eq!(progress.current_position, 0);
        assert_eq!(progress.total_attempts, 0);
        
        progress.update_position(100, 150);
        assert_eq!(progress.current_position, 100);
        assert_eq!(progress.total_attempts, 150);
        
        progress.mark_found("foundpassword".to_string());
        assert_eq!(progress.found_password, Some("foundpassword".to_string()));
    }
    
    #[test]
    fn test_save_load_progress() {
        let temp_file = NamedTempFile::new().unwrap();
        let file_path = temp_file.path().to_path_buf();
        
        let original_progress = ProgressState::new(
            "$6$testsalt$hash".to_string(),
            "/path/to/wordlist.txt".to_string(),
            1000,
        );
        
        save_progress(&original_progress, &file_path).unwrap();
        let loaded_progress = load_progress(&file_path).unwrap();
        
        assert_eq!(original_progress.target_hash, loaded_progress.target_hash);
        assert_eq!(original_progress.wordlist_path, loaded_progress.wordlist_path);
        assert_eq!(original_progress.current_position, loaded_progress.current_position);
    }
}
