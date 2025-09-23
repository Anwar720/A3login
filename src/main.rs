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
fn get_password_hash(username: &str, db_path: &str) -> Option<String> {
    let mut db = open_db(db_path);
    for result in db.records() {
        let record = result.ok()?;
        if record[0] == username.to_string() {
            return Some(record[1].to_string()); 
        }
    }
    None
}

fn is_valid_password(username: &str, password: &str, db_path: &str) -> bool {
    let hash = get_password_hash(username, db_path).unwrap();

    let parsed_hash = PasswordHash::new(&hash).expect("Invalid hash format");
    Argon2::default()
        .verify_password(password.as_bytes(),&parsed_hash).is_ok()
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