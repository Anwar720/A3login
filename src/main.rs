use std::fs::File;
use std::env;
use argon2::{ Argon2,PasswordVerifier};
use argon2::password_hash::PasswordHash;

// open csv file
fn open_db(file_path: &str) -> csv::Reader<File> {
    let file = File::open(file_path).expect("Error! Password database not found!");
    // create csv reader without headers
    csv::ReaderBuilder::new()
        .has_headers(false)
        .from_reader(file)
}

// look through csv file for username
// return true if found, false otherwise
fn is_valid_username(username: &str, db_path: &str) -> bool {
    let mut db = open_db(db_path);
    let users: Vec<String> = db
        .records()
        .filter_map(|r| r.ok())
        .map(|r| r[0].to_string())
        .collect();

    users.iter().any(|user| user == username)
}

// get password hash for username
// return Some(hash) if found, None otherwise
fn get_password_hash(username: &str, db_path: &str) -> Option<String> {
    let mut db = open_db(db_path);

    db.records()
        .filter_map(|r| r.ok())                 
        .find(|record| record.get(0).map_or(false, |u| u == username))
        .and_then(|record| record.get(1).map(|h| h.to_string()))
}

// verify password against hash
// return true if valid, false otherwise
fn is_valid_password(username: &str, password: &str, db_path: &str) -> bool {
    if let Some(hash) = get_password_hash(username, db_path) {
        if let Ok(parsed_hash) = PasswordHash::new(&hash) {
            return Argon2::default()
                .verify_password(password.as_bytes(), &parsed_hash)
                .is_ok();
        }
    }
    false
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let db_file_path = &args[1]; 
    let mut username = String::new();
    let mut password = String::new();
    // validate db file exists
    let is_valid_db_path = File::open(db_file_path).is_ok();
    if !is_valid_db_path {
        println!("Error! Password database not found!");
        return;
    }

    println!("Enter username: ");
    std::io::stdin().read_line(&mut username).expect("Failed to read username");

    if is_valid_username(username.trim(), db_file_path) {
        println!("Enter password: ");
        std::io::stdin().read_line(&mut password).expect("Failed to read password");

        if is_valid_password(username.trim(), password.trim(), db_file_path) {
            println!("Access Granted!");
        } else {
            println!("Error! Access Denied!");
        }
    } else {
        println!("Error! Access Denied!");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    // test valid username and invalid username
    fn test_is_valid_username() {
        let db_path = "db.csv";
        assert!(is_valid_username("admin", db_path));
        assert!(!is_valid_username("random_user", db_path));       
    }
    
    #[test]
    //test hash retrieval for valid and invalid username
    fn test_get_password_hash() {
        let db_path = "db.csv";
        assert_eq!(get_password_hash("admin", db_path).unwrap(), "$argon2id$v=19$m=19456,t=2,p=1$difPUw5AhyFN/URJZ0IY8g$VDC5PPK0Lx8IeI6LttXQ90zL3BuH/AAQV1ndGEovpPY");
        assert!(get_password_hash("random_user", db_path).is_none());      
    }

    #[test]
    // test valid password and invalid password
    fn test_is_valid_password() {
        let db_path = "db.csv";
        assert!(is_valid_password("guest", "guest", db_path));
        assert!(!is_valid_password("guest", "wrongpassword", db_path));     
    }

}