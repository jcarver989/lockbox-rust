use lockbox::Lockbox;
use serde::Deserialize;
use std::error::Error;
use std::path::Path;

#[derive(Debug, Deserialize)]
pub struct LastPassExportRecord {
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
pub fn import_from_lastpass(
    export_file: &Path,
    lockbox: &mut Lockbox,
) -> Result<(), Box<dyn Error>> {
    let mut reader = csv::Reader::from_path(export_file)?;
    for result in reader.deserialize::<LastPassExportRecord>() {
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
