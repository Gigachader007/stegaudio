use std::collections::{HashMap, HashSet};
use anyhow::{Result, anyhow};
use bincode::config;

const DATA:         [u8; 8] = [0x17, 0xF2, 0xB6, 0x1F, 0xA1, 0x28, 0x5B, 0x0A];
const LZMA_DATA:    [u8; 8] = [0x8C, 0x5D, 0xC6, 0x4A, 0xC7, 0xCA, 0x1A, 0x5D];
const ENC_DATA:     [u8; 8] = [0x47, 0xA3, 0xEA, 0x7A, 0x79, 0x12, 0x16, 0x58];
const ENC_LZMA_DATA:[u8; 8] = [0xC7, 0x3C, 0xA3, 0x89, 0x2E, 0xBB, 0xA3, 0x33];

pub trait DataContainerImpl {
    fn list_files(&self) -> HashSet<String>;
    fn read_file(&self, name: String) -> Option<Vec<u8>>;
    fn remove_file(&mut self, name: String) -> Option<()>;
    fn add_file(&mut self, name: String, data: Vec<u8>);

    fn get_data(&self) -> Result<Vec<u8>>;
}

pub struct DataContainer{
    map: HashMap<String, Vec<u8>>,
    size: usize
}

impl DataContainer {
    pub fn empty(size: usize) -> DataContainer {
        DataContainer { map: HashMap::new(), size: size }
    }
    pub fn try_new(data: Vec<u8>) -> Result<DataContainer> {
        let (map, _) = bincode::decode_from_slice(&data[8..], config::standard())?;
        Ok(DataContainer{map, size: data.len()})
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

    fn add_file(&mut self, name: String, data: Vec<u8>){
        self.map.insert(name, data);
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