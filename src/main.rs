use std::fs::File;

// open csv file
fn open_db() -> csv::Reader<File> {
    let file = File::open("src/db.csv").expect("Could not open db file");
    // create csv reader without headers
    csv::ReaderBuilder::new()
        .has_headers(false)
        .from_reader(file)
}

// look through csv file for username
fn is_valid_username(username: &str, mut db: csv::Reader<File>) -> bool {
    let users: Vec<String> = db
        .records() 
        .filter_map(|r| r.ok())
        .map(|r| r[0].to_string())
        .collect();
        
    println!("Users collected: {:?}", users);
    users.iter().any(|user| user == username)
}


fn main() {
    let mut username = String::new();
    let mut password = String::new();
    let db = open_db();

    println!("Enter username: ");
    std::io::stdin().read_line(&mut username).expect("Failed to read username");

    // checks if username is valid before asking for password
    if is_valid_username(username.trim(), db) {
        println!("Enter password: ");
        std::io::stdin().read_line(&mut password).expect("Failed to read password");
    } else {
        println!("Login failed!");
    }


}
