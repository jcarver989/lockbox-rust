use super::data_types::{ByteVec, DataKey, MasterKey};
use super::functions::{
    decrypt, encrypt, generate_data_key, generate_nonce, generate_random_alphanumeric_string,
};
use crate::error::Error;
use crate::protobufs::{encrypted_object::EncryptionAlgorithm, EncryptedObject};
use rand::{CryptoRng, Rng};

/// Encrypts and decrypts objects using "envelope encryption" + a Master Key.
///
/// Each object is encrypted with a unique Data Key, which is in turn encrypted with the specified Master Key.
/// Then, the encrypted Data Key is stored along with the encrypted object.
pub struct Encryptor<T: CryptoRng + Rng> {
    rng: T,
    master_key: MasterKey,
    pub algorithm: EncryptionAlgorithm,
}

impl<T: CryptoRng + Rng> Encryptor<T> {
    pub fn new(rng: T, master_key: MasterKey) -> Encryptor<T> {
        Encryptor {
            rng,
            master_key,
            algorithm: EncryptionAlgorithm::LibsodiumSecretbox,
        }
    }

    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<EncryptedObject, Error> {
        let encrypted_object = {
            let data_key = generate_data_key(&mut self.rng);
            let encrypted_data_key = encrypt(
                data_key.as_bytes(),
                &self.master_key,
                &generate_nonce(&mut self.rng),
            )?;

            let encrypted_data = encrypt(&plaintext, &data_key, &generate_nonce(&mut self.rng))?;
            let mut encrypted_object = EncryptedObject::default();
            encrypted_object.algorithm = self.algorithm as i32;
            encrypted_object.encrypted_data_key = Some(encrypted_data_key);
            encrypted_object.encrypted_data = Some(encrypted_data);
            encrypted_object
        };

        Ok(encrypted_object)
    }

    pub fn decrypt(&mut self, encrypted_object: &EncryptedObject) -> Result<Vec<u8>, Error> {
        let data_key = {
            let data_key_bytes = decrypt(
                encrypted_object.encrypted_data_key.as_ref().unwrap(),
                &self.master_key,
            )?;
            DataKey::new(data_key_bytes)
        };
        decrypt(encrypted_object.encrypted_data.as_ref().unwrap(), &data_key)
    }

    pub fn generate_random_id(&mut self) -> String {
        generate_random_alphanumeric_string(&mut self.rng, 16)
    }
}

#[cfg(test)]
mod tests {
    use super::super::functions::{derive_master_key_from_password, generate_salt};
    use super::*;
    use rand::prelude::*;
    use rand::rngs::StdRng;

    const MASTER_PASSWORD: &str = "password-123";

    #[test]
    fn it_encrypts_and_decrypts() {
        let mut rng = StdRng::from_entropy();
        let master_key =
            derive_master_key_from_password(MASTER_PASSWORD, &generate_salt(&mut rng)).unwrap();
        let mut encryptor = Encryptor::new(rng, master_key);
        let plaintext = b"Hello world!".to_vec();
        let encrypted_message = encryptor.encrypt(&plaintext).unwrap();
        let decrypted_message = encryptor.decrypt(&encrypted_message).unwrap();
        assert_eq!(&plaintext, &decrypted_message);
    }

    #[test]
    fn it_does_not_generate_same_ciphertext_or_nonce_twice() {
        let mut rng = StdRng::from_entropy();
        let master_key =
            derive_master_key_from_password(MASTER_PASSWORD, &generate_salt(&mut rng)).unwrap();
        let mut encryptor = Encryptor::new(rng, master_key);
        let plaintext = b"Hello world!".to_vec();

        let encrypted_data1 = encryptor
            .encrypt(&plaintext)
            .unwrap()
            .encrypted_data
            .unwrap();
        let encrypted_data2 = encryptor
            .encrypt(&plaintext)
            .unwrap()
            .encrypted_data
            .unwrap();

        assert_ne!(&encrypted_data1.nonce, &encrypted_data2.nonce);
        assert_ne!(&encrypted_data1.ciphertext, &encrypted_data2.ciphertext);
    }
}
