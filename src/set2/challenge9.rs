

pub fn pad_using_pkcs7(block_size: u8, input: &[u8]) -> Vec<u8> {
    if block_size <= 0 || input.len() <= 0 {
        panic!("block_size and input must be greater than 0");
    }

    let remainder = block_size - (input.len() % block_size as usize) as u8;

    let padding = match remainder {
        0 => vec![block_size; block_size as usize],
        _ => vec![remainder; remainder as usize]
    };

    [input, &padding].concat()
}

#[cfg(test)]
mod tests {

    use super::*;


    #[test]
    fn run_challenge9() {
        let block_size: u8 = 20;
        let input = "YELLOW SUBMARINE".as_bytes();
        let expected = "YELLOW SUBMARINE\x04\x04\x04\x04".as_bytes();

        let result = pad_using_pkcs7(block_size, &input);

        assert_eq!(expected, result)
    }

}