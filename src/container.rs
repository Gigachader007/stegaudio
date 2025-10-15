use std::collections::{HashMap, HashSet};
use anyhow::{Result, anyhow};
use bincode::config;
use chacha20poly1305::{aead::{Aead, AeadMut, OsRng}, AeadCore, KeyInit, XChaCha20Poly1305};
use pbkdf2::password_hash::SaltString;
use sha2::{digest::generic_array::GenericArray, Digest, Sha256};
use lzma::EXTREME_PRESET;

pub const DATA:         [u8; 8] = [0x17, 0xF2, 0xB6, 0x1F, 0xA1, 0x28, 0x5B, 0x0A];
pub const LZMA_DATA:    [u8; 8] = [0x8C, 0x5D, 0xC6, 0x4A, 0xC7, 0xCA, 0x1A, 0x5D];
pub const ENC_DATA:     [u8; 8] = [0x47, 0xA3, 0xEA, 0x7A, 0x79, 0x12, 0x16, 0x58];
pub const ENC_LZMA_DATA:[u8; 8] = [0xC7, 0x3C, 0xA3, 0x89, 0x2E, 0xBB, 0xA3, 0x33];

pub trait DataContainerImpl {
    fn list_files(&self) -> HashSet<String>;
    fn read_file(&self, name: String) -> Option<Vec<u8>>;
    fn remove_file(&mut self, name: String) -> Option<()>;
    fn add_file(&mut self, name: String, data: Vec<u8>) -> Result<()>;

    fn get_data(&self) -> Result<Vec<u8>>;
}

pub struct DataContainerXChaCha20Poly1305Lzma{
    map: HashMap<String, Vec<u8>>,
    size: usize,
    cipher: XChaCha20Poly1305,
    salt: String
}

impl DataContainerImpl for DataContainerXChaCha20Poly1305Lzma {
    fn list_files(&self) -> HashSet<String> {
        self.map.iter().map(|(name, _)| name.clone()).collect()
    }
    fn read_file(&self, name: String) -> Option<Vec<u8>> {
        match lzma::decompress(&self.map.get(&name).cloned()?) {
            Ok(data) => {
                Some(data)
            }
            Err(_) => {
                None
            }
        }
    }
    fn remove_file(&mut self, name: String) -> Option<()> {
        self.map.remove(&name)?;
        Some(())
    }
    fn add_file(&mut self, name: String, data: Vec<u8>) -> Result<()>{
        self.map.insert(name, lzma::compress(&data, EXTREME_PRESET)?);
        Ok(())
    }
    fn get_data(&self) -> Result<Vec<u8>> {
        let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);

        let vec = bincode::encode_to_vec(self.map.clone(), config::standard())?;

        let encrypted = self.cipher.encrypt(&nonce, vec.as_ref());
        let encrypted = match encrypted {
            Ok(encrypted) => {
                encrypted
            }
            Err(_) => {
                return Err(anyhow!("Failed to encrypt container..."));
            }
        };

        let enc_size = encrypted.len();
        let enc_size_bytes: [u8; std::mem::size_of::<usize>()] = enc_size.to_le_bytes();

        let nonce = nonce.to_vec();
        // [magic 8 bytes] [nonce 24 bytes] [enc_size 8 bytes] [salt_size 8 bytes] [salt_str salt_size bytes] [enc_data enc_size bytes]

        let salt_bytes = self.salt.as_bytes().to_vec();

        let salt_size = salt_bytes.len();
        let salt_size_bytes: [u8; std::mem::size_of::<usize>()] = salt_size.to_le_bytes();

        let mut res = [&ENC_LZMA_DATA[..], &nonce[..], &enc_size_bytes[..], &salt_size_bytes[..], &salt_bytes[..], &encrypted[..]].concat();
        if res.len() < self.size {
            res.resize(self.size, 0u8);
        }
        Ok(res)
    }
}

impl DataContainerXChaCha20Poly1305Lzma {
    pub fn empty(size: usize, password: String) -> Result<Self> {
        let binding = SaltString::generate(&mut OsRng);
        let salt_str = binding.as_str().to_string();
        let key = pbkdf2::pbkdf2_hmac_array::<Sha256, 32>(password.as_bytes(), salt_str.as_bytes(), 600_000);
        let key = match GenericArray::from_exact_iter(key){
            Some(key) => key,
            None => return Err(anyhow!("Failed to get key from password...")),
        };
        Ok(Self { map: HashMap::new(), size: size, cipher: XChaCha20Poly1305::new(&key), salt: salt_str})
    }
    pub fn try_new(data: Vec<u8>, password: String) -> Result<Self> {
        let nonce: [u8; 24] = data[8..8+24].try_into()?;

        let enc_size: [u8; std::mem::size_of::<usize>()] = data[8+24..8+24+std::mem::size_of::<usize>()].try_into()?;
        let enc_size = usize::from_le_bytes(enc_size);
        
        let salt_size: [u8; std::mem::size_of::<usize>()] = data[8+24+std::mem::size_of::<usize>()..8+24+2*std::mem::size_of::<usize>()].try_into()?;
        let salt_size = usize::from_le_bytes(salt_size);
        // [magic 8 bytes] [nonce 24 bytes] [enc_size 8 bytes] [salt_size 8 bytes] [salt_str salt_size bytes] [enc_data enc_size bytes]
        
        let nonce = match GenericArray::from_exact_iter(nonce) {
            Some(array) => {
                array
            }
            None => {
                return Err(anyhow!("Failed to extract nonce in container..."));
            }
        };

        let salt_str = data[8+24+2*std::mem::size_of::<usize>()..8+24+2*std::mem::size_of::<usize>()+salt_size].to_vec();
        let salt_str = String::from_utf8(salt_str)?;

        let key = pbkdf2::pbkdf2_hmac_array::<Sha256, 32>(password.as_bytes(), salt_str.as_bytes(), 600_000);
        let key = match GenericArray::from_exact_iter(key){
            Some(key) => key,
            None => return Err(anyhow!("Failed to get key from password...")),
        };

        let cipher = XChaCha20Poly1305::new(&key);

        let raw_data = data[8+24+2*std::mem::size_of::<usize>()+salt_size..8+24+2*std::mem::size_of::<usize>()+salt_size+enc_size].to_vec();
        let decrypted = cipher.decrypt(&nonce, raw_data.as_ref());
        
        let res_data = match decrypted {
            Ok(data) => {
                data
            }
            Err(_) => {
                return Err(anyhow!("Failed to decrypt data in container"));
            }
        };

        let (map, _) = bincode::decode_from_slice(&res_data[..], config::standard())?;

        Ok(Self{map: map, size: data.len(), cipher, salt: salt_str})
    }
}

pub struct DataContainerXChaCha20Poly1305{
    map: HashMap<String, Vec<u8>>,
    size: usize,
    cipher: XChaCha20Poly1305,
    salt: String
}

impl DataContainerXChaCha20Poly1305 {
    pub fn empty(size: usize, password: String) -> Result<Self> {
        let binding = SaltString::generate(&mut OsRng);
        let salt_str = binding.as_str().to_string();
        let key = pbkdf2::pbkdf2_hmac_array::<Sha256, 32>(password.as_bytes(), salt_str.as_bytes(), 600_000);
        let key = match GenericArray::from_exact_iter(key){
            Some(key) => key,
            None => return Err(anyhow!("Failed to get key from password...")),
        };
        Ok(Self { map: HashMap::new(), size: size, cipher: XChaCha20Poly1305::new(&key), salt: salt_str})
    }
    pub fn try_new(data: Vec<u8>, password: String) -> Result<Self> {
        let nonce: [u8; 24] = data[8..8+24].try_into()?;

        let enc_size: [u8; std::mem::size_of::<usize>()] = data[8+24..8+24+std::mem::size_of::<usize>()].try_into()?;
        let enc_size = usize::from_le_bytes(enc_size);
        
        let salt_size: [u8; std::mem::size_of::<usize>()] = data[8+24+std::mem::size_of::<usize>()..8+24+2*std::mem::size_of::<usize>()].try_into()?;
        let salt_size = usize::from_le_bytes(salt_size);
        // [magic 8 bytes] [nonce 24 bytes] [enc_size 8 bytes] [salt_size 8 bytes] [salt_str salt_size bytes] [enc_data enc_size bytes]
        
        let nonce = match GenericArray::from_exact_iter(nonce) {
            Some(array) => {
                array
            }
            None => {
                return Err(anyhow!("Failed to extract nonce in container..."));
            }
        };

        let salt_str = data[8+24+2*std::mem::size_of::<usize>()..8+24+2*std::mem::size_of::<usize>()+salt_size].to_vec();
        let salt_str = String::from_utf8(salt_str)?;

        let key = pbkdf2::pbkdf2_hmac_array::<Sha256, 32>(password.as_bytes(), salt_str.as_bytes(), 600_000);
        let key = match GenericArray::from_exact_iter(key){
            Some(key) => key,
            None => return Err(anyhow!("Failed to get key from password...")),
        };

        let cipher = XChaCha20Poly1305::new(&key);

        let raw_data = data[8+24+2*std::mem::size_of::<usize>()+salt_size..8+24+2*std::mem::size_of::<usize>()+salt_size+enc_size].to_vec();
        let decrypted = cipher.decrypt(&nonce, raw_data.as_ref());
        
        let res_data = match decrypted {
            Ok(data) => {
                data
            }
            Err(_) => {
                return Err(anyhow!("Failed to decrypt data in container"));
            }
        };

        let (map, _) = bincode::decode_from_slice(&res_data[..], config::standard())?;

        Ok(Self{map: map, size: data.len(), cipher, salt: salt_str})
    }
}
impl DataContainerImpl for DataContainerXChaCha20Poly1305 {
    fn list_files(&self) -> HashSet<String> {
        self.map.iter().map(|(name, _)| name.clone()).collect()
    }

    fn read_file(&self, name: String) -> Option<Vec<u8>> {
        self.map.get(&name).cloned()
    }

    fn remove_file(&mut self, name: String) -> Option<()> {
        self.map.remove(&name)?;
        Some(())
    }

    fn add_file(&mut self, name: String, data: Vec<u8>) -> Result<()> {
        self.map.insert(name, data);
        Ok(())
    }

        fn get_data(&self) -> Result<Vec<u8>> {
        let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);

        let vec = bincode::encode_to_vec(self.map.clone(), config::standard())?;

        let encrypted = self.cipher.encrypt(&nonce, vec.as_ref());
        let encrypted = match encrypted {
            Ok(encrypted) => {
                encrypted
            }
            Err(_) => {
                return Err(anyhow!("Failed to encrypt container..."));
            }
        };

        let enc_size = encrypted.len();
        let enc_size_bytes: [u8; std::mem::size_of::<usize>()] = enc_size.to_le_bytes();

        let nonce = nonce.to_vec();
        // [magic 8 bytes] [nonce 24 bytes] [enc_size 8 bytes] [salt_size 8 bytes] [salt_str salt_size bytes] [enc_data enc_size bytes]

        let salt_bytes = self.salt.as_bytes().to_vec();

        let salt_size = salt_bytes.len();
        let salt_size_bytes: [u8; std::mem::size_of::<usize>()] = salt_size.to_le_bytes();

        let mut res = [&ENC_DATA[..], &nonce[..], &enc_size_bytes[..], &salt_size_bytes[..], &salt_bytes[..], &encrypted[..]].concat();
        if res.len() < self.size {
            res.resize(self.size, 0u8);
        }
        Ok(res)
    }
}

pub struct DataContainerLzma {
    map: HashMap<String, Vec<u8>>,
    size: usize
}

impl DataContainerLzma {
    pub fn empty(size: usize) -> Self {
        Self { map: HashMap::new(), size: size }
    }
    pub fn try_new(data: Vec<u8>) -> Result<Self> {
        let (map, _) = bincode::decode_from_slice(&data[8..], config::standard())?;
        Ok(Self{map, size: data.len()})
    }
}

impl DataContainerImpl for DataContainerLzma {
    fn list_files(&self) -> HashSet<String> {
        self.map.iter().map(|(name, _)| name.clone()).collect()
    }
    fn read_file(&self, name: String) -> Option<Vec<u8>> {
        match lzma::decompress(&self.map.get(&name).cloned()?) {
            Ok(data) => {
                Some(data)
            }
            Err(_) => {
                None
            }
        }
    }
    fn remove_file(&mut self, name: String) -> Option<()> {
        self.map.remove(&name)?;
        Some(())
    }
    fn add_file(&mut self, name: String, data: Vec<u8>) -> Result<()>{
        self.map.insert(name, lzma::compress(&data, EXTREME_PRESET)?);
        Ok(())
    }
    fn get_data(&self) -> Result<Vec<u8>> {
        let vec = bincode::encode_to_vec(self.map.clone(), config::standard())?;
        let mut vec = [&LZMA_DATA[..], &vec[..]].concat().to_vec();
        if vec.len() > self.size {
            return Err(anyhow!("Container to big to insert in WAV file!"));
        }
        vec.resize(self.size, 0u8);
        Ok(vec)
    }
}

pub struct DataContainer{
    map: HashMap<String, Vec<u8>>,
    size: usize
}

impl DataContainer {
    pub fn empty(size: usize) -> Self {
        Self { map: HashMap::new(), size: size }
    }
    pub fn try_new(data: Vec<u8>) -> Result<Self> {
        let (map, _) = bincode::decode_from_slice(&data[8..], config::standard())?;
        Ok(Self{map, size: data.len()})
    }
}

impl DataContainerImpl for DataContainer{
    fn list_files(&self) -> HashSet<String> {
        self.map.iter().map(|(name, _)| name.clone()).collect()
    }

    fn read_file(&self, name: String) -> Option<Vec<u8>> {
        self.map.get(&name).cloned()
    }

    fn remove_file(&mut self, name: String) -> Option<()> {
        self.map.remove(&name)?;
        Some(())
    }

    fn add_file(&mut self, name: String, data: Vec<u8>) -> Result<()> {
        self.map.insert(name, data);
        Ok(())
    }

    fn get_data(&self) -> Result<Vec<u8>> {
        let vec = bincode::encode_to_vec(self.map.clone(), config::standard())?;
        let mut vec = [&DATA[..], &vec[..]].concat().to_vec();
        if vec.len() > self.size {
            return Err(anyhow!("Container to big to insert in WAV file!"));
        }
        vec.resize(self.size, 0u8);
        Ok(vec)
    }
}