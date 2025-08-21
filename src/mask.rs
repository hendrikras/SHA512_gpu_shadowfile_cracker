use anyhow::{anyhow, Result};

/// Parse a character range string into a character set
/// Supports formats like:
/// - "0-4" -> [0, 1, 2, 3, 4]
/// - "a-z" -> [a, b, c, ..., z]
/// - "A-Z" -> [A, B, C, ..., Z]
/// - "!@#$%^&*" -> [!, @, #, $, %, ^, &, *]
pub fn parse_range(range: &str) -> Result<Vec<u8>> {
    if range.contains('-') && range.len() >= 3 {
        // Range format like "a-z" or "0-9"
        let chars: Vec<char> = range.chars().collect();
        if chars.len() == 3 && chars[1] == '-' {
            let start = chars[0] as u8;
            let end = chars[2] as u8;
            if start <= end {
                return Ok((start..=end).collect());
            }
        }
        // Multi-range or complex format - fall through to literal parsing
    }

    // Literal character set
    Ok(range.as_bytes().to_vec())
}

#[cfg(test)]
mod range_tests {
    use super::*;

    #[test]
    fn test_parse_digit_range() {
        let result = parse_range("0-4").unwrap();
        assert_eq!(result, vec![b'0', b'1', b'2', b'3', b'4']);
    }

    #[test]
    fn test_parse_alpha_range() {
        let result = parse_range("a-c").unwrap();
        assert_eq!(result, vec![b'a', b'b', b'c']);
    }

    #[test]
    fn test_parse_literal_chars() {
        let result = parse_range("!@#$").unwrap();
        assert_eq!(result, vec![b'!', b'@', b'#', b'$']);
    }
}

/// Mask character sets
pub const CHARSET_LOWER: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
pub const CHARSET_UPPER: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
pub const CHARSET_DIGITS: &[u8] = b"0123456789";
pub const CHARSET_SPECIAL: &[u8] = b"!@#$%^&*()_+-=[]{}|;:,.<>?";
/// Represents a mask position with its character set
#[derive(Debug, Clone)]
pub struct MaskPosition {
    pub charset: Vec<u8>,
}

/// Mask pattern parser and generator
#[derive(Debug, Clone)]
pub struct MaskPattern {
    pub positions: Vec<MaskPosition>,
    pub total_combinations: u64,
}

impl MaskPattern {
    /// Parse a mask string into a MaskPattern with custom ranges
    /// Supported patterns:
    /// ?l = lowercase letters (a-z)
    /// ?u = uppercase letters (A-Z)  
    /// ?d = digits (0-9 or custom digit range)
    /// ?s = special characters
    /// ?a = all printable ASCII (a-z, A-Z, 0-9, special)
    /// literal characters = themselves
    pub fn from_mask_with_ranges(mask: &str, digit_range: Option<&str>, character_range: Option<&str>) -> Result<Self> {
        let custom_digits = if let Some(range) = digit_range {
            parse_range(range)?
        } else {
            CHARSET_DIGITS.to_vec()
        };

        let custom_special = if let Some(range) = character_range {
            parse_range(range)?
        } else {
            CHARSET_SPECIAL.to_vec()
        };

        let mut positions = Vec::new();
        let mut chars = mask.chars().peekable();

        while let Some(ch) = chars.next() {
            if ch == '?' {
                // Special mask character
                if let Some(&next_ch) = chars.peek() {
                    chars.next(); // consume the next character
                    let charset = match next_ch {
                        'l' => CHARSET_LOWER.to_vec(),
                        'u' => CHARSET_UPPER.to_vec(),
                        'd' => custom_digits.clone(),
                        's' => custom_special.clone(),
                        'a' => {
                            let mut all = Vec::new();
                            all.extend_from_slice(CHARSET_LOWER);
                            all.extend_from_slice(CHARSET_UPPER);
                            all.extend(&custom_digits);
                            all.extend(&custom_special);
                            all
                        }
                        '?' => vec![b'?'], // Literal ? character
                        _ => return Err(anyhow!("Unknown mask character: ?{}", next_ch)),
                    };
                    positions.push(MaskPosition { charset });
                } else {
                    return Err(anyhow!("Incomplete mask pattern: trailing ?"));
                }
            } else {
                // Literal character
                positions.push(MaskPosition {
                    charset: vec![ch as u8],
                });
            }
        }

        if positions.is_empty() {
            return Err(anyhow!("Empty mask pattern"));
        }

        // Calculate total combinations
        let mut total_combinations = 1u64;
        for position in &positions {
            total_combinations = total_combinations
                .checked_mul(position.charset.len() as u64)
                .ok_or_else(|| anyhow!("Mask pattern too large - would overflow"))?;
        }

        Ok(MaskPattern {
            positions,
            total_combinations,
        })
    }

    /// Parse a mask string into a MaskPattern
    /// Supported patterns:
    /// ?l = lowercase letters (a-z)
    /// ?u = uppercase letters (A-Z)  
    /// ?d = digits (0-9)
    /// ?s = special characters
    /// ?a = all printable ASCII (a-z, A-Z, 0-9, special)
    /// literal characters = themselves
    pub fn from_mask(mask: &str) -> Result<Self> {
        Self::from_mask_with_ranges(mask, None, None)
    }

    /// Generate password at specific index
    pub fn generate_password(&self, index: u64) -> Result<String> {
        if index >= self.total_combinations {
            return Err(anyhow!("Index {} out of range for mask pattern", index));
        }

        let mut password = Vec::with_capacity(self.positions.len());
        let mut remaining_index = index;

        // Convert index to password by treating it as a number in mixed radix
        for position in self.positions.iter().rev() {
            let charset_size = position.charset.len() as u64;
            let char_index = remaining_index % charset_size;
            password.push(position.charset[char_index as usize]);
            remaining_index /= charset_size;
        }

        password.reverse();
        String::from_utf8(password).map_err(|e| anyhow!("Invalid UTF-8 in generated password: {}", e))
    }

    /// Generate all passwords from the mask pattern
    pub fn generate_all_passwords(&self) -> Result<Vec<String>> {
        if self.total_combinations > 1_000_000 {
            return Err(anyhow!(
                "Mask pattern generates {} combinations - too large for memory. Use batch generation instead.",
                self.total_combinations
            ));
        }

        let mut passwords = Vec::with_capacity(self.total_combinations as usize);
        for i in 0..self.total_combinations {
            passwords.push(self.generate_password(i)?);
        }
        Ok(passwords)
    }

    /// Generate passwords in batches for memory efficiency
    pub fn generate_batch(&self, start_index: u64, batch_size: u64) -> Result<Vec<String>> {
        let end_index = (start_index + batch_size).min(self.total_combinations);
        let mut passwords = Vec::with_capacity((end_index - start_index) as usize);

        for i in start_index..end_index {
            passwords.push(self.generate_password(i)?);
        }

        Ok(passwords)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_digit_mask() {
        let pattern = MaskPattern::from_mask("?d?d").unwrap();
        assert_eq!(pattern.total_combinations, 100); // 10 * 10

        assert_eq!(pattern.generate_password(0).unwrap(), "00");
        assert_eq!(pattern.generate_password(1).unwrap(), "01");
        assert_eq!(pattern.generate_password(10).unwrap(), "10");
        assert_eq!(pattern.generate_password(99).unwrap(), "99");
    }

    #[test]
    fn test_mixed_mask() {
        let pattern = MaskPattern::from_mask("a?d").unwrap();
        assert_eq!(pattern.total_combinations, 10); // 1 * 10

        assert_eq!(pattern.generate_password(0).unwrap(), "a0");
        assert_eq!(pattern.generate_password(9).unwrap(), "a9");
    }

    #[test]
    fn test_lowercase_mask() {
        let pattern = MaskPattern::from_mask("?l?l").unwrap();
        assert_eq!(pattern.total_combinations, 676); // 26 * 26

        assert_eq!(pattern.generate_password(0).unwrap(), "aa");
        assert_eq!(pattern.generate_password(25).unwrap(), "az");
        assert_eq!(pattern.generate_password(26).unwrap(), "ba");
    }

    #[test]
    fn test_literal_question_mark() {
        let pattern = MaskPattern::from_mask("test??").unwrap();
        assert_eq!(pattern.total_combinations, 1);
        assert_eq!(pattern.generate_password(0).unwrap(), "test?");
    }

    #[test]
    fn test_batch_generation() {
        let pattern = MaskPattern::from_mask("?d?d").unwrap();
        let batch = pattern.generate_batch(0, 10).unwrap();
        assert_eq!(batch.len(), 10);
        assert_eq!(batch[0], "00");
        assert_eq!(batch[9], "09");
    }

    #[test]
    fn test_custom_digit_range() {
        let pattern = MaskPattern::from_mask_with_ranges("?d?d", Some("0-2"), None).unwrap();
        assert_eq!(pattern.total_combinations, 9); // 3 * 3 = 9

        assert_eq!(pattern.generate_password(0).unwrap(), "00");
        assert_eq!(pattern.generate_password(1).unwrap(), "01");
        assert_eq!(pattern.generate_password(2).unwrap(), "02");
        assert_eq!(pattern.generate_password(3).unwrap(), "10");
        assert_eq!(pattern.generate_password(8).unwrap(), "22");
    }

    #[test]
    fn test_custom_character_range() {
        let pattern = MaskPattern::from_mask_with_ranges("?s?s", None, Some("!@")).unwrap();
        assert_eq!(pattern.total_combinations, 4); // 2 * 2 = 4

        assert_eq!(pattern.generate_password(0).unwrap(), "!!");
        assert_eq!(pattern.generate_password(1).unwrap(), "!@");
        assert_eq!(pattern.generate_password(2).unwrap(), "@!");
        assert_eq!(pattern.generate_password(3).unwrap(), "@@");
    }
}
