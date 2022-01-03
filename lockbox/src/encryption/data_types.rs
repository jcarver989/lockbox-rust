use xsalsa20poly1305::aead::{
    generic_array::{ArrayLength, GenericArray},
    AeadCore, NewAead,
};
use xsalsa20poly1305::XSalsa20Poly1305;
use zeroize::Zeroize;

/// A trait representing a fixed-length vector of bytes
pub trait ByteVec {
    type NBytes: ArrayLength<u8>;
    fn new(bytes: Vec<u8>) -> Self;
    fn as_bytes(&self) -> &[u8];
}

/// A trait representing an Encryption Key -- e.g. DataKey, MasterKey etc.
pub trait EncryptionKey: ByteVec {
    fn as_generic_array(&self) -> &GenericArray<u8, <XSalsa20Poly1305 as NewAead>::KeySize> {
        self.as_bytes().into()
    }
}

/// A Master Encryption Key, which is used to encrypt/decrypt Data Encryption Keys
pub struct MasterKey(Vec<u8>);

impl EncryptionKey for MasterKey {}
impl ByteVec for MasterKey {
    type NBytes = <XSalsa20Poly1305 as NewAead>::KeySize;

    fn new(bytes: Vec<u8>) -> Self {
        MasterKey(bytes)
    }

    fn as_bytes(&self) -> &[u8] {
        self.0.as_slice()
    }
}

impl Drop for MasterKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// A Data Encryption Key which is used to encrypt/decrypt data
pub struct DataKey(Vec<u8>);
impl DataKey {
    pub fn to_master_key(&self) -> MasterKey {
        MasterKey::new(self.0.clone())
    }
}

impl EncryptionKey for DataKey {}
impl ByteVec for DataKey {
    type NBytes = <XSalsa20Poly1305 as NewAead>::KeySize;

    fn new(bytes: Vec<u8>) -> Self {
        DataKey(bytes)
    }

    fn as_bytes(&self) -> &[u8] {
        self.0.as_slice()
    }
}

impl Drop for DataKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// A fixed-length Nonce
pub struct Nonce(Vec<u8>);
impl Nonce {
    pub fn as_generic_array(&self) -> &GenericArray<u8, <XSalsa20Poly1305 as AeadCore>::NonceSize> {
        self.as_bytes().into()
    }
}

impl ByteVec for Nonce {
    type NBytes = <XSalsa20Poly1305 as AeadCore>::NonceSize;

    fn new(bytes: Vec<u8>) -> Self {
        Nonce(bytes)
    }

    fn as_bytes(&self) -> &[u8] {
        self.0.as_slice()
    }
}

/// A fixed-length Salt for a KDF (key-derivation-function)
pub struct Salt(String);

impl Salt {
    pub fn new(salt: String) -> Self {
        Salt(salt)
    }

    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}
