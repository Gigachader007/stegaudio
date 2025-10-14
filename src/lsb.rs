use anyhow::{Result, anyhow};

pub fn extract_lsb_size(size: usize, bit_count: usize) -> usize {
    return size * bit_count / 8;
}

pub fn extract_lsb_data<T>(data: *const T, size: usize, bit_count: usize) -> Vec<u8> {
    let mut res_vec = Vec::new();

    let size_of_type = std::mem::size_of::<T>();

    unsafe{
        let mut adding_byte: u8 = 0;
        let mut counter: usize = 0;
        for i in 0..size {
            let mut last_byte = *((data.add(i) as usize + size_of_type - 1) as *const u8);
            for _ in 0..bit_count {
                adding_byte = (adding_byte << 1) | (last_byte & 1);
                last_byte = last_byte >> 1;
                counter += 1;

                if counter % 8 == 0 && counter != 0 {
                    res_vec.push(adding_byte);
                    adding_byte = 0;
                    counter = 0;
                }
            }
        }
    }

    res_vec
}

pub fn insert_lsb_data<T>(data: *const T, size: usize, bit_count: usize, insert_data: Vec<u8>) -> Result<()> {
    if extract_lsb_size(size, bit_count) < insert_data.len() {
        return Err(anyhow!("Failed to insert lsb data, insertion data too big"));
    }
    let size_of_type = std::mem::size_of::<T>();
    unsafe {
        let mut counter: usize = 0;
        'main_loop: for i in 0..size {
            let mut last_byte = *((data.add(i) as usize + size_of_type - 1) as *const u8);
            last_byte = (last_byte >> bit_count) << bit_count; // clear last bits

            for _ in 0..bit_count {
                let crnt_bit_in_insert_data = 7 - (counter % 8);
                let index_in_insert_data = counter / 8;
                if index_in_insert_data >= insert_data.len() {
                    break 'main_loop;
                }
                let crnt_bit_in_original_data = counter % bit_count;

                last_byte |= ((insert_data[index_in_insert_data as usize] >> crnt_bit_in_insert_data) & 1) << crnt_bit_in_original_data;
                counter += 1;
            }
            
            *((data.add(i) as usize + size_of_type - 1) as *mut u8) = last_byte; // write to mem
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests{
    use super::*;
    #[test]
    fn read_data_test(){
        let data: [u8; 8] = [255, 255, 255, 255, 255, 255, 255, 255];

        let ptr = data.as_ptr();
        let data = extract_lsb_data::<u8>(ptr, data.len(), 2);

        println!("{:?}", data);
    }
    #[test]
    fn write_data_test(){
        let data: [u8; 4] = [0, 0, 0, 0];
        let ptr = data.as_ptr();

        let secret_data: [u8; 1] = [0b11010101];

        insert_lsb_data::<u8>(ptr, data.len(), 2, secret_data.to_vec()).unwrap();

        println!("{:?}", data);
    }
    #[test]
    fn read_write_data_test(){
        let data: [u8; 16] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let secret_data: [u8; 10] = [13, 37, 74, 51, 130, 146, 180, 107, 59, 193];

        println!("{:?}", data);
        
        insert_lsb_data(data.as_ptr(), data.len(),5, secret_data.to_vec()).unwrap();

        let readed_data = extract_lsb_data(data.as_ptr(), data.len(), 5);

        println!("{:?} {:?}", secret_data, readed_data);
        println!("{:?}", data);
    }
}