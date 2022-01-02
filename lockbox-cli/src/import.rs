use lockbox::Lockbox;
use serde::Deserialize;
use std::error::Error;
use std::path::Path;

pub trait Importer {
    fn import(file: &Path, lockbox: &mut Lockbox) -> Result<(), Box<dyn Error>>;
}

#[derive(Debug, Deserialize)]
pub struct LastPassRecord {
    pub url: String,
    pub username: String,
    pub password: String,
    pub totp: String,
    pub extra: String,
    pub name: String,
    pub grouping: String,
    pub fav: String,
}

/// Imports a LastPass CSV file into a Lockbox file
impl Importer for LastPassRecord {
    fn import(file: &Path, lockbox: &mut Lockbox) -> Result<(), Box<dyn Error>> {
        let mut reader = csv::Reader::from_path(file)?;
        for result in reader.deserialize::<LastPassRecord>() {
            let record = result?;
            let notes = if record.extra != "" {
                Some(record.extra)
            } else {
                None
            };

            lockbox.add_password(record.url, record.username, record.password, notes)?;
        }

        lockbox.save()?;
        Ok(())
    }
}
