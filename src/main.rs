use crate::wav::WAV;


mod wav;
mod lsb;

fn main() -> Result<(), Box<dyn std::error::Error>> {

    Ok(())
}

#[cfg(test)]
mod tests{
    use std::collections::HashMap;

    use bincode::config;

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

        match wav.data {
            wav::DataType::U8(ptr) => {
                lsb::insert_lsb_data(ptr, wav.size, bit_count, encoded_bytes).unwrap();
            },
            wav::DataType::I16(ptr) => {
                lsb::insert_lsb_data(ptr, wav.size, bit_count, encoded_bytes).unwrap();
            },
            wav::DataType::I24(ptr) => {
                lsb::insert_lsb_data(ptr, wav.size, bit_count, encoded_bytes).unwrap();
            },
            wav::DataType::I32(ptr) => {
                lsb::insert_lsb_data(ptr, wav.size, bit_count, encoded_bytes).unwrap();
            },
            wav::DataType::F32(ptr) => {
                lsb::insert_lsb_data(ptr, wav.size, bit_count, encoded_bytes).unwrap();
            },
        }

        std::fs::write("music.wav", bytes).unwrap();
        std::fs::remove_file(filename).unwrap();
    }

    #[test]
    fn read_files_in_audio(){
        let bytes = std::fs::read("music.wav").unwrap();
        let wav = wav::WAV::new(&bytes).unwrap();

        let bit_count = 2;
        
        let data = match wav.data {
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
        };

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

        match wav.data {
            wav::DataType::U8(ptr) => {
                lsb::insert_lsb_data(ptr, wav.size, bit_count, clear_data).unwrap();
            },
            wav::DataType::I16(ptr) => {
                lsb::insert_lsb_data(ptr, wav.size, bit_count, clear_data).unwrap();
            },
            wav::DataType::I24(ptr) => {
                lsb::insert_lsb_data(ptr, wav.size, bit_count, clear_data).unwrap();
            },
            wav::DataType::I32(ptr) => {
                lsb::insert_lsb_data(ptr, wav.size, bit_count, clear_data).unwrap();
            },
            wav::DataType::F32(ptr) => {
                lsb::insert_lsb_data(ptr, wav.size, bit_count, clear_data).unwrap();
            },
        }

        std::fs::write("music.wav", bytes).unwrap();
    }

    #[test]
    fn add_test_data_in_audio() {
        let bytes = std::fs::read("music.wav").unwrap();
        let wav = wav::WAV::new(&bytes).unwrap();

        let bit_count = 2;

        let mut secret_data = "Super secret text".to_string().as_bytes().to_vec();
        secret_data.resize(lsb::extract_lsb_size(wav.size, bit_count), 0u8);

        match wav.data {
            wav::DataType::U8(ptr) => {
                lsb::insert_lsb_data(ptr, wav.size, bit_count, secret_data).unwrap();
            },
            wav::DataType::I16(ptr) => {
                lsb::insert_lsb_data(ptr, wav.size, bit_count, secret_data).unwrap();
            },
            wav::DataType::I24(ptr) => {
                lsb::insert_lsb_data(ptr, wav.size, bit_count, secret_data).unwrap();
            },
            wav::DataType::I32(ptr) => {
                lsb::insert_lsb_data(ptr, wav.size, bit_count, secret_data).unwrap();
            },
            wav::DataType::F32(ptr) => {
                lsb::insert_lsb_data(ptr, wav.size, bit_count, secret_data).unwrap();
            },
        }

        std::fs::write("music.wav", bytes).unwrap();
    }

    #[test]
    fn read_test_data_in_audio() {
        let bytes = std::fs::read("music.wav").unwrap();
        let wav = wav::WAV::new(&bytes).unwrap();

        let bit_count = 2;

        let data = match wav.data {
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
        };

        let string = String::from_utf8_lossy(&data).to_string();
        println!("{}", string);
    }
}