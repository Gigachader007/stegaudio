use std::io::Write;

use crate::{container::{DataContainer, DataContainerImpl, DataContainerLzma, DataContainerXChaCha20Poly1305, DataContainerXChaCha20Poly1305Lzma, DATA, ENC_DATA, ENC_LZMA_DATA, LZMA_DATA}, lsb::extract_lsb_size, wav::WAV};
use clap::Parser;

mod wav;
mod lsb;
mod container;

use anyhow::{Result,anyhow};

#[derive(Parser, Debug)]
struct StegAudioArgs{
    /// Input wav file
    #[arg(long)]
    input: String,

    /// Bit count in LSB encoding/decoding
    #[arg(long, default_value_t = 2)]
    bit_count: usize,

    /// Create new container inside wav file
    /// 0 - don't create container
    /// 1 - create container
    /// 2 - create container with compression
    /// 3 - create container with encryption
    /// 4 - create container with compression and encryption
    #[arg(long, default_value_t = 0, verbatim_doc_comment)]
    new: u32,

    /// List files in wav file
    #[arg(long, default_value_t = false)]
    list: bool,

    /// Add file(s) to wav file
    #[arg(long, num_args = 0.., value_delimiter = ' ')]
    add: Option<Vec<String>>,

    /// Remove file(s) from wav
    #[arg(long, num_args = 0.., value_delimiter = ' ')]
    remove: Option<Vec<String>>,

    /// Extract file(s) from wav
    #[arg(long, num_args = 0.., value_delimiter = ' ')]
    extract: Option<Vec<String>>
}

fn extract_wav_lsb_data(wav: &WAV, bit_count: usize) -> Vec<u8> {
    match wav.data {
        wav::DataType::U8(ptr) => {
            lsb::extract_lsb_data(ptr, wav.size, bit_count)
        },
        wav::DataType::I16(ptr) => {
            lsb::extract_lsb_data(ptr, wav.size, bit_count)
        },
        wav::DataType::I24(ptr) => {
            lsb::extract_lsb_data(ptr, wav.size, bit_count)
        },
        wav::DataType::I32(ptr) => {
            lsb::extract_lsb_data(ptr, wav.size, bit_count)
        },
        wav::DataType::F32(ptr) => {
            lsb::extract_lsb_data(ptr, wav.size, bit_count)
        },
    }
}
fn insert_wav_lsb_data(wav: &WAV, bit_count: usize, insert_data: Vec<u8>) -> Result<()> {
    match wav.data {
        wav::DataType::U8(ptr) => {
            lsb::insert_lsb_data(ptr, wav.size, bit_count, insert_data)
        },
        wav::DataType::I16(ptr) => {
            lsb::insert_lsb_data(ptr, wav.size, bit_count, insert_data)
        },
        wav::DataType::I24(ptr) => {
            lsb::insert_lsb_data(ptr, wav.size, bit_count, insert_data)
        },
        wav::DataType::I32(ptr) => {
            lsb::insert_lsb_data(ptr, wav.size, bit_count, insert_data)
        },
        wav::DataType::F32(ptr) => {
            lsb::insert_lsb_data(ptr, wav.size, bit_count, insert_data)
        },
    }
}

fn let_me_password() -> Result<String>{
    print!("Write password: ");
    std::io::stdout().flush()?;
    
    let password = rpassword::read_password()?;

    Ok(password)
}

fn main() -> Result<()> {
    let args = StegAudioArgs::parse();

    let bytes = std::fs::read(args.input.clone())?;
    let wav = wav::WAV::new(&bytes)?;

    let mut container: Box<dyn DataContainerImpl> = match args.new {
        0 => {
            let data = extract_wav_lsb_data(&wav, args.bit_count);
            if data.len() < 8 {
                return Err(anyhow!("Audio file to small to be container!"));
            }

            let magic = data[..8].try_into()?;

            match magic {
                DATA => {
                    Box::new(DataContainer::try_new(data)?)
                }
                LZMA_DATA => {
                    Box::new(DataContainerLzma::try_new(data)?)
                }
                ENC_DATA => {
                    Box::new(DataContainerXChaCha20Poly1305::try_new(data, let_me_password()?)?)
                }
                ENC_LZMA_DATA => {
                    Box::new(DataContainerXChaCha20Poly1305Lzma::try_new(data, let_me_password()?)?)
                }
                _ => {
                    return Err(anyhow!("Failed to read data!"));
                }
            }
        },
        1 => {
            Box::new(DataContainer::empty(extract_lsb_size(wav.size, args.bit_count)))
        }
        2 => {
            Box::new(DataContainerLzma::empty(extract_lsb_size(wav.size, args.bit_count)))
        }
        3 => {
            Box::new(DataContainerXChaCha20Poly1305::empty(extract_lsb_size(wav.size, args.bit_count), let_me_password()?))
        }
        4 => {
            Box::new(DataContainerXChaCha20Poly1305Lzma::empty(extract_lsb_size(wav.size, args.bit_count), let_me_password()?))
        }
        _ => {
            return Err(anyhow!("Invalid new option!"));
        }
    };

    if args.list {
        println!("Files inside container: ");
        for name in container.list_files() {
            println!("\t{}", name);
        }
        println!();
    }
    if args.add.is_some() {
        let name = args.add.unwrap();
        for name in name {
            println!("Adding {} to container...", name.clone());
            match std::fs::read(&name) {
                Ok(bytes) => {
                    container.add_file(name.clone(), bytes)?;
                    println!("File {} added successfully!", name);
                }
                Err(err) => {
                    println!("Failed to add {} to container! Error: {}", name, err);
                }
            }
        }
    }
    if args.extract.is_some() {
        let name = args.extract.unwrap();
        for name in name {
            println!("Extracting {}...", name.clone());
            let bytes = container.read_file(name.clone());
            if bytes.is_some() {
                let bytes = bytes.unwrap();
                std::fs::write(name.clone(), bytes)?;
                println!("{} extracted successfully!", name);
            }
            else{
                println!("Failed to extract {}", name);
            }
        }
    }
    if args.remove.is_some() {
        let name = args.remove.unwrap();
        for name in name {
            let res = container.remove_file(name.clone());
            if res.is_some() {
                println!("Successfully {} removed!", name);
            }
            else{
                println!("Failed to remove {}", name);
            }
        }
    }
    
    insert_wav_lsb_data(&wav, args.bit_count, container.get_data()?)?;

    std::fs::write(args.input, bytes)?;

    Ok(())
}

#[cfg(test)]
mod tests{
    use std::collections::HashMap;

    use bincode::config;

    use crate::extract_wav_lsb_data;
    use crate::insert_wav_lsb_data;
    use crate::wav;
    use crate::lsb;

    #[test]
    fn add_file_to_audio(){
        let bytes = std::fs::read("music.wav").unwrap();
        let wav = wav::WAV::new(&bytes).unwrap();

        let bit_count = 2;
        let mut map = HashMap::<String, Vec<u8>>::new();

        let filename = "text.txt";
        let read_text_file = std::fs::read(filename).unwrap();
        map.insert(filename.to_string(), read_text_file);

        let mut encoded_bytes = bincode::encode_to_vec(map, config::standard()).unwrap();
        encoded_bytes.resize(lsb::extract_lsb_size(wav.size, bit_count), 0u8);

        insert_wav_lsb_data(&wav, bit_count, encoded_bytes).unwrap();

        std::fs::write("music.wav", bytes).unwrap();
    }

    #[test]
    fn read_files_in_audio(){
        let bytes = std::fs::read("music.wav").unwrap();
        let wav = wav::WAV::new(&bytes).unwrap();

        let bit_count = 2;
        
        let data = extract_wav_lsb_data(&wav, bit_count);

        let (map, size): (HashMap<String, Vec<u8>>, usize) = bincode::decode_from_slice(&data, config::standard()).unwrap();

        println!("{:?}", map);
        println!("{}", size); 

        for (name, data) in map {
            std::fs::write(name, data).unwrap();
        }
    }

    #[test]
    fn clear_lsb_data_in_audio(){
        let bytes = std::fs::read("music.wav").unwrap();
        let wav = wav::WAV::new(&bytes).unwrap();

        let bit_count = 2;

        let secret_data_size = lsb::extract_lsb_size(wav.size, bit_count);
        let mut clear_data = Vec::<u8>::new();
        clear_data.resize(secret_data_size, 0u8);

        insert_wav_lsb_data(&wav, bit_count, clear_data).unwrap();

        std::fs::write("music.wav", bytes).unwrap();
    }

    #[test]
    fn add_test_data_in_audio() {
        let bytes = std::fs::read("music.wav").unwrap();
        let wav = wav::WAV::new(&bytes).unwrap();

        let bit_count = 2;

        let mut secret_data = "Super secret text".to_string().as_bytes().to_vec();
        secret_data.resize(lsb::extract_lsb_size(wav.size, bit_count), 0u8);

        insert_wav_lsb_data(&wav, bit_count, secret_data).unwrap();

        std::fs::write("music.wav", bytes).unwrap();
    }

    #[test]
    fn read_test_data_in_audio() {
        let bytes = std::fs::read("music.wav").unwrap();
        let wav = wav::WAV::new(&bytes).unwrap();

        let bit_count = 2;

        let data = extract_wav_lsb_data(&wav, bit_count);

        let string = String::from_utf8_lossy(&data).to_string();
        println!("{}", string);
    }
}