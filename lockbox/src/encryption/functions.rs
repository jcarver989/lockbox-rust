use crate::error::Error;
use argon2::{
    password_hash,
    password_hash::{PasswordHasher, SaltString},
    Argon2,
};
use rand::{distributions::Alphanumeric, CryptoRng, Rng};

use xsalsa20poly1305::{KEY_SIZE, NONCE_SIZE};

use super::data_types::{ByteVec, DataKey, EncryptionKey, MasterKey, Nonce, Salt};

use crate::protobufs::EncryptedData;
use xsalsa20poly1305::aead::{generic_array::GenericArray, Aead, NewAead};
use xsalsa20poly1305::XSalsa20Poly1305;

pub fn derive_master_key_from_password(password: &str, salt: &Salt) -> Result<MasterKey, Error> {
    let key_bytes = Argon2::default()
        .hash_password(password.as_bytes(), salt.as_str())?
        .hash
        .ok_or(password_hash::Error::PhcStringInvalid)?
        .as_bytes()
        .to_vec();

    Ok(MasterKey::new(key_bytes))
}

pub fn generate_data_key(rng: &mut impl Rng) -> DataKey {
    let mut key_bytes = vec![0; KEY_SIZE];
    rng.fill_bytes(&mut key_bytes);
    DataKey::new(key_bytes)
}

pub fn generate_nonce(rng: &mut impl Rng) -> Nonce {
    let mut nonce_bytes = vec![0; NONCE_SIZE];
    rng.fill_bytes(&mut nonce_bytes);
    Nonce::new(nonce_bytes)
}

pub fn generate_salt<T: CryptoRng + Rng>(rng: &mut T) -> Salt {
    let salt = SaltString::generate(rng);
    Salt::new(String::from(salt.as_str()))
}

pub fn generate_random_alphanumeric_string<T: CryptoRng + Rng>(
    rng: &mut T,
    n_chars: usize,
) -> String {
    rng.sample_iter(&Alphanumeric)
        .take(n_chars)
        .map(char::from)
        .collect()
}

pub fn encrypt<T: EncryptionKey>(
    plaintext: &[u8],
    key: &T,
    nonce: &Nonce,
) -> Result<EncryptedData, Error> {
    let cipher = XSalsa20Poly1305::new(key.as_generic_array());
    let mut encrypted_data = EncryptedData::default();
    encrypted_data.nonce = nonce.as_bytes().to_owned();
    encrypted_data.ciphertext = cipher.encrypt(nonce.as_generic_array(), plaintext)?;
    Ok(encrypted_data)
}

pub fn decrypt<T: EncryptionKey>(
    encrypted_data: &EncryptedData,
    key: &T,
) -> Result<Vec<u8>, Error> {
    let cipher = XSalsa20Poly1305::new(key.as_generic_array());
    let nonce = GenericArray::from_slice(&encrypted_data.nonce);
    cipher
        .decrypt(&nonce, encrypted_data.ciphertext.as_ref())
        .map_err(Error::from)
}
