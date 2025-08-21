use sha_crypt::sha512_simple;

fn main() {
    let password = "test123";
    let salt = "aKFCChRVHAK8PxFM";
    
    // Generate a hash using the standard library
    let params = sha_crypt::Sha512Params::from_salt(salt).unwrap();
    let hash = sha512_simple(password, &params).unwrap();
    
    println!("Password: {}", password);
    println!("Salt: {}", salt);
    println!("Generated hash: {}", hash);
    
    // Test verification
    let is_valid = sha_crypt::sha512_check(password, &hash).is_ok();
    println!("Verification: {}", is_valid);
}
