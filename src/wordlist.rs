use anyhow::{anyhow, Result};
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;

/// Load wordlist from file, returning a vector of password candidates
pub fn load_wordlist(path: &PathBuf) -> Result<Vec<String>> {
    let file = File::open(path)
        .map_err(|e| anyhow!("Failed to open wordlist file '{}': {}", path.display(), e))?;
    
    let reader = BufReader::new(file);
    let mut wordlist = Vec::new();
    
    for (line_num, line) in reader.lines().enumerate() {
        let line = line.map_err(|e| anyhow!("Error reading line {}: {}", line_num + 1, e))?;
        let password = line.trim().to_string();
        
        // Skip empty lines
        if !password.is_empty() {
            wordlist.push(password);
        }
    }
    
    if wordlist.is_empty() {
        return Err(anyhow!("Wordlist file is empty or contains no valid entries"));
    }
    
    Ok(wordlist)
}

/// Generate common password mutations for a base wordlist
pub fn generate_mutations(base_wordlist: &[String]) -> Vec<String> {
    let mut mutations = Vec::new();
    
    for password in base_wordlist {
        // Add original
        mutations.push(password.clone());
        
        // Add common mutations
        mutations.push(password.to_uppercase());
        mutations.push(password.to_lowercase());
        mutations.push(format!("{}1", password));
        mutations.push(format!("{}!", password));
        mutations.push(format!("{}123", password));
        mutations.push(format!("1{}", password));
        mutations.push(format!("{}2023", password));
        mutations.push(format!("{}2024", password));
        
        // Capitalize first letter
        if let Some(first_char) = password.chars().next() {
            let capitalized = format!("{}{}", 
                first_char.to_uppercase(), 
                password.chars().skip(1).collect::<String>().to_lowercase()
            );
            if capitalized != *password {
                mutations.push(capitalized);
            }
        }
        
        // Leet speak substitutions
        let leet = password
            .replace('a', "@")
            .replace('e', "3")
            .replace('i', "1")
            .replace('o', "0")
            .replace('s', "5")
            .replace('t', "7");
        if leet != *password {
            mutations.push(leet);
        }
    }
    
    mutations
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;
    
    #[test]
    fn test_load_wordlist() {
        let mut temp_file = NamedTempFile::new().unwrap();
        writeln!(temp_file, "password123").unwrap();
        writeln!(temp_file, "admin").unwrap();
        writeln!(temp_file, "").unwrap(); // Empty line should be skipped
        writeln!(temp_file, "root").unwrap();
        
        let wordlist = load_wordlist(&temp_file.path().to_path_buf()).unwrap();
        
        assert_eq!(wordlist.len(), 3);
        assert_eq!(wordlist[0], "password123");
        assert_eq!(wordlist[1], "admin");
        assert_eq!(wordlist[2], "root");
    }
    
    #[test]
    fn test_generate_mutations() {
        let base = vec!["password".to_string()];
        let mutations = generate_mutations(&base);
        
        assert!(mutations.contains(&"password".to_string()));
        assert!(mutations.contains(&"PASSWORD".to_string()));
        assert!(mutations.contains(&"password1".to_string()));
        assert!(mutations.contains(&"Password".to_string()));
        assert!(mutations.contains(&"p@ssw0rd".to_string()));
    }
}
