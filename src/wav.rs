use std::os::raw::c_void;

use anyhow::{Result, anyhow};

#[derive(Debug)]
pub struct WAV{
    pub riff_header: *const RIFF_HEADER,

    pub data: DataType,
    pub size: usize,
    
    pub fmt_chunk: *const FMT_CHUNK
}

const RIFF: [u8; 4] = ['R' as u8, 'I' as u8, 'F' as u8, 'F' as u8];
const WAVE: [u8; 4] = ['W' as u8, 'A' as u8, 'V' as u8, 'E' as u8];
const FMT:  [u8; 4] = ['f' as u8, 'm' as u8, 't' as u8, ' ' as u8];
const DATA: [u8; 4] = ['d' as u8, 'a' as u8, 't' as u8, 'a' as u8];

#[derive(Debug)]
#[repr(C)]
struct RIFF_HEADER{
    RIFF: [u8; 4],
    ChunkSize: u32,
    WAVE: [u8; 4]
}

#[derive(Debug)]
#[repr(C)]
struct CHUNK_INFO{
    chunk_id: [u8; 4],
    chunk_size: u32
}

#[derive(Debug)]
#[repr(C)]
struct FMT_CHUNK{
    audio_format: u16,
    num_channels: u16,
    sample_rate: u32,
    byte_rate: u32,
    block_align: u16,
    bits_per_sample: u16
}

#[derive(Debug)]
#[repr(C)]
pub enum DataType{
    U8(*const u8),
    I16(*const i16),
    I24(*const [u8; 3]),
    I32(*const i32),
    F32(*const f32)
}

impl WAV {
    pub fn new(bytes: &Vec<u8>) -> Result<Self> {
        let riff_header = bytes[0..std::mem::size_of::<RIFF_HEADER>()].as_ptr() as *const RIFF_HEADER;
        let mut fmt_chunk: *const FMT_CHUNK = std::ptr::null();
        
        let mut data: DataType = DataType::U8(std::ptr::null());
        let mut size: usize = 0;
        unsafe{
            if (*riff_header).RIFF != RIFF || (*riff_header).WAVE != WAVE {
                return Err(anyhow!("Not WAVE Format!"));
            }
            let mut offset = std::mem::size_of::<RIFF_HEADER>();
            let mut just_ptr = std::ptr::null();
            let mut byte_size = 0;
            while fmt_chunk == std::ptr::null() || just_ptr == std::ptr::null() {
                let chunk_info = bytes[offset..offset+std::mem::size_of::<CHUNK_INFO>()].as_ptr() as *const CHUNK_INFO;
                offset += std::mem::size_of::<CHUNK_INFO>();
                match (*chunk_info).chunk_id {
                    FMT => {
                        fmt_chunk = bytes[offset..offset + ((*chunk_info).chunk_size as usize)].as_ptr() as *const FMT_CHUNK;
                    }
                    DATA => {
                        just_ptr = bytes[offset..offset + ((*chunk_info).chunk_size as usize)].as_ptr() as *const u8;
                        byte_size = (*chunk_info).chunk_size as usize;
                    }
                    _ => {

                    }
                }
                if fmt_chunk != std::ptr::null() && just_ptr != std::ptr::null() {
                    break;
                }
                offset += (*chunk_info).chunk_size as usize;
            }
            
            size = byte_size / ((*fmt_chunk).bits_per_sample as usize / 8);
            match (*fmt_chunk).bits_per_sample {
                8 => {
                    data = DataType::U8(just_ptr as *const u8);
                }
                16 => {
                    data = DataType::I16(just_ptr as *const i16);
                }
                24 => {
                    data = DataType::I24(just_ptr as *const [u8; 3]);
                }
                32 => {
                    data = DataType::I32(just_ptr as *const i32);
                }
                _ => {
                    return Err(anyhow!("Failed to parse bits per sample in WAV"));
                }
            }
        }

        Ok(WAV{riff_header, fmt_chunk, size, data})
    }
}


#[cfg(test)]
mod tests{
    use super::*;

    #[test]
    fn read_wav_file(){
        let bytes = std::fs::read("music.wav").unwrap();
        let wav = WAV::new(&bytes).unwrap();

        println!("{:?}", wav);
    }

    #[test]
    fn reverse_wav_file(){
        let bytes = std::fs::read("music.wav").unwrap();
        let wav = WAV::new(&bytes).unwrap();

        unsafe{
            for i in 0..(wav.size/2) {
                match wav.data {
                    DataType::U8(ptr) => {
                        let val = ptr.add(i) as *mut u8;
                        let last_val = ptr.add(wav.size - 1 - i) as *mut u8;
                        (*last_val, *val) = (*val, *last_val);
                    },
                    DataType::I16(ptr) => {
                        let val = ptr.add(i) as *mut i16;
                        let last_val = ptr.add(wav.size - 1 - i) as *mut i16;
                        (*last_val, *val) = (*val, *last_val);
                    },
                    DataType::I24(ptr) => {
                        let val = ptr.add(i) as *mut [u8; 3];
                        let last_val = ptr.add(wav.size - 1 - i) as *mut [u8; 3];
                        (*last_val, *val) = (*val, *last_val);
                    },
                    DataType::I32(ptr) => {
                        let val = ptr.add(i) as *mut i32;
                        let last_val = ptr.add(wav.size - 1 - i) as *mut i32;
                        (*last_val, *val) = (*val, *last_val);
                    },
                    DataType::F32(ptr) => {
                        let val = ptr.add(i) as *mut f32;
                        let last_val = ptr.add(wav.size - 1 - i) as *mut f32;
                        (*last_val, *val) = (*val, *last_val);
                    },
                }
            }
        }

        std::fs::write("music.wav", bytes).unwrap();
    }
}