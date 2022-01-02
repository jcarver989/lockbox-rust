use crate::encryption::{
    data_types::Salt, derive_master_key_from_password, generate_salt, Encryptor,
};
use prost::Message;
use rand::prelude::*;
use rand::rngs::StdRng;
use std::fs::{create_dir_all, read, write};
use std::io::Cursor;
use std::path::{Path, PathBuf};

use crate::error::Error;
use crate::protobufs;

pub struct Lockbox {
    lockbox: protobufs::Lockbox,
    encryptor: Encryptor<StdRng>,
    master_key_salt: Salt,
    file_path: PathBuf,
}

pub struct DecryptedPassword {
    pub id: String,
    pub url: String,
    pub username: String,
    pub password: String,
    pub notes: String,
}

impl Lockbox {
    pub fn create(file_path: &Path, master_password: &str) -> Result<Lockbox, Error> {
        let (encryptor, master_key_salt) = {
            let mut rng = StdRng::from_entropy();
            let master_key_salt = generate_salt(&mut rng);
            let master_key = derive_master_key_from_password(master_password, &master_key_salt)?;
            (Encryptor::new(rng, master_key), master_key_salt)
        };

        let mut lockbox = Lockbox {
            lockbox: protobufs::Lockbox::default(),
            encryptor,
            master_key_salt,
            file_path: file_path.to_owned(),
        };

        lockbox.save()?;
        Ok(lockbox)
    }

    pub fn load(file_path: &Path, master_password: &str) -> Result<Lockbox, Error> {
        let (encrypted_lockbox, master_key_salt) = {
            let bytes = Cursor::new(read(file_path)?);
            let encrypted_lockbox = protobufs::EncryptedLockboxFile::decode(bytes)?;
            (
                encrypted_lockbox
                    .lockbox
                    .ok_or(Error::new_invalid_data_error(
                        "EncryptedLockboxFile 'lockbox' field was None",
                    ))?,
                Salt::new(encrypted_lockbox.master_key_salt),
            )
        };

        let mut encryptor = {
            let master_key = derive_master_key_from_password(master_password, &master_key_salt)?;
            Encryptor::new(StdRng::from_entropy(), master_key)
        };

        let lockbox = {
            let bytes = encryptor.decrypt(&encrypted_lockbox)?;
            protobufs::Lockbox::decode(Cursor::new(&bytes))?
        };

        Ok(Lockbox {
            lockbox,
            encryptor,
            master_key_salt,
            file_path: file_path.to_owned(),
        })
    }

    pub fn add_password(
        &mut self,
        url: String,
        username: String,
        password: String,
        notes: Option<String>,
    ) -> Result<protobufs::EncryptedPassword, Error> {
        let mut encrypted_password = protobufs::EncryptedPassword::default();
        encrypted_password.id = self.encryptor.generate_random_id();
        encrypted_password.username = username;
        encrypted_password.url = url;
        encrypted_password.encrypted_fields = Some({
            let mut password_fields = protobufs::DecryptedPasswordFields::default();
            password_fields.password = password;
            password_fields.notes = notes.unwrap_or("".to_owned());
            self.encryptor.encrypt(&password_fields.encode_to_vec())?
        });

        self.lockbox
            .encrypted_passwords
            .push(encrypted_password.clone());

        Ok(encrypted_password)
    }

    pub fn edit_password(
        &mut self,
        id: String,
        url: Option<String>,
        username: Option<String>,
        password: Option<String>,
        notes: Option<String>,
    ) -> Result<(), Error> {
        let encrypted_password = self
            .lockbox
            .encrypted_passwords
            .iter_mut()
            .find(|p| p.id == id)
            .ok_or(Error::new_invalid_data_error(
                "Could not find encrypted password with specified id",
            ))?;

        if let Some(new_url) = url {
            encrypted_password.url = new_url;
        }

        if let Some(new_username) = username {
            encrypted_password.username = new_username;
        }

        if password.is_some() || notes.is_some() {
            let mut decrypted_fields =
                Self::decrypt_password_fields(&mut self.encryptor, encrypted_password)?;

            if let Some(new_password) = password {
                decrypted_fields.password = new_password;
            }

            if let Some(new_notes) = notes {
                decrypted_fields.notes = new_notes;
            }

            encrypted_password.encrypted_fields =
                Some(self.encryptor.encrypt(&decrypted_fields.encode_to_vec())?);
        }

        Ok(())
    }

    pub fn get_encrypted_passwords(&self) -> &[protobufs::EncryptedPassword] {
        &self.lockbox.encrypted_passwords
    }

    pub fn find_password_by_id(&mut self, id: &str) -> Option<DecryptedPassword> {
        self.find_password(|p| p.id == id)
    }

    pub fn find_password_by_url(&mut self, url: &str) -> Option<DecryptedPassword> {
        self.find_password(|p| p.url == url)
    }

    pub fn save(&mut self) -> Result<(), Error> {
        match self.file_path.parent() {
            None => (),
            Some(p) => create_dir_all(p)?,
        };

        let encrypted_lockbox = {
            let mut encrypted_lockbox = protobufs::EncryptedLockboxFile::default();
            let lockbox_bytes = self.lockbox.encode_to_vec();
            encrypted_lockbox.lockbox = Some(self.encryptor.encrypt(&lockbox_bytes)?);
            encrypted_lockbox.master_key_salt = self.master_key_salt.as_str().to_string();
            encrypted_lockbox
        };
        write(&self.file_path, encrypted_lockbox.encode_to_vec())?;
        Ok(())
    }

    fn find_password<T: FnMut(&&protobufs::EncryptedPassword) -> bool>(
        &mut self,
        predicate: T,
    ) -> Option<DecryptedPassword> {
        let encryptor = &mut self.encryptor;
        self.lockbox
            .encrypted_passwords
            .iter()
            .find(predicate)
            .map(|p| Self::decrypt_password(encryptor, p).unwrap())
    }

    fn decrypt_password(
        encryptor: &mut Encryptor<StdRng>,
        encrypted_password: &protobufs::EncryptedPassword,
    ) -> Result<DecryptedPassword, Error> {
        let decrypted_fields = Self::decrypt_password_fields(encryptor, encrypted_password)?;

        Ok(DecryptedPassword {
            id: encrypted_password.id.clone(),
            url: encrypted_password.url.clone(),
            username: encrypted_password.username.clone(),
            password: decrypted_fields.password.clone(),
            notes: decrypted_fields.notes.clone(),
        })
    }

    fn decrypt_password_fields(
        encryptor: &mut Encryptor<StdRng>,
        encrypted_password: &protobufs::EncryptedPassword,
    ) -> Result<protobufs::DecryptedPasswordFields, Error> {
        encryptor
            .decrypt(encrypted_password.encrypted_fields.as_ref().unwrap())
            .and_then(|bytes| {
                protobufs::DecryptedPasswordFields::decode(Cursor::new(bytes)).map_err(Error::from)
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{distributions::Alphanumeric, Rng};
    use std::env::temp_dir;
    use std::path::PathBuf;

    const MASTER_PASSWORD: &str = "password-123";

    #[test]
    fn it_saves_and_loads() {
        let lockbox_file = &rand_file_path();
        Lockbox::create(lockbox_file, MASTER_PASSWORD).unwrap();
        let lockbox2 = Lockbox::load(lockbox_file, MASTER_PASSWORD).unwrap();
        assert_eq!(lockbox2.lockbox.encrypted_passwords.len(), 0);
    }

    #[test]
    fn it_adds_a_password() {
        let lockbox_file = &rand_file_path();
        let mut lockbox = Lockbox::create(lockbox_file, MASTER_PASSWORD).unwrap();

        lockbox
            .add_password(
                String::from("https://amazon.com"),
                String::from("user"),
                String::from("password-123"),
                Some(String::from("notes")),
            )
            .unwrap();

        lockbox
            .add_password(
                String::from("https://foo.com"),
                String::from("user"),
                String::from("password-456"),
                Some(String::from("notes")),
            )
            .unwrap();

        lockbox.save().unwrap();

        let mut lockbox2 = Lockbox::load(lockbox_file, MASTER_PASSWORD).unwrap();
        let password = lockbox2.find_password_by_url("https://amazon.com");
        assert_eq!(password.unwrap().password, "password-123");
    }

    #[test]
    fn it_edits_a_password() {
        let lockbox_file = &rand_file_path();
        let mut lockbox = Lockbox::create(lockbox_file, MASTER_PASSWORD).unwrap();

        let password = lockbox
            .add_password(
                String::from("https://amazon.com"),
                String::from("user"),
                String::from("password-123"),
                Some(String::from("notes")),
            )
            .unwrap();

        lockbox
            .edit_password(
                password.id.clone(),
                Some(String::from("https://alibaba.com")),
                Some(String::from("username")),
                Some(String::from("password-456")),
                Some(String::from("notes")),
            )
            .unwrap();
        lockbox.save().unwrap();

        let mut lockbox2 = Lockbox::load(lockbox_file, MASTER_PASSWORD).unwrap();
        let decrypted = &lockbox2
            .find_password_by_url("https://alibaba.com")
            .unwrap();
        assert_eq!(decrypted.password, "password-456");
        assert_eq!(decrypted.notes, "notes");
    }

    #[test]
    fn it_finds_a_password_by_id() {
        let lockbox_file = &rand_file_path();
        let mut lockbox = Lockbox::create(lockbox_file, MASTER_PASSWORD).unwrap();
        lockbox
            .add_password(
                String::from("https://amazon.com"),
                String::from("user"),
                String::from("password-123"),
                Some(String::from("notes")),
            )
            .unwrap();
        lockbox.save().unwrap();

        let mut lockbox2 = Lockbox::load(lockbox_file, MASTER_PASSWORD).unwrap();
        let password = lockbox2.find_password_by_url("https://amazon.com").unwrap();
        assert_eq!(password.password, "password-123");
    }

    fn rand_file_path() -> PathBuf {
        let filename: String = rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(10)
            .map(char::from)
            .collect();
        let mut tmp = temp_dir();
        tmp.push(filename);
        tmp
    }
}
