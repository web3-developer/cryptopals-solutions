

pub fn hex_to_bytes(hex: &str) -> Vec<u8> {
    hex::decode(hex).unwrap()
}

pub fn bytes_to_hex(bytes: &[u8]) -> String {
    hex::encode(bytes.as_ref())
}

use base64::{Engine as _, engine::{general_purpose}};

pub fn base64_to_bytes(base64: &str) -> Vec<u8> {
    general_purpose::STANDARD.decode(base64).unwrap()
}

pub fn bytes_to_base64(bytes: &[u8]) -> String {
    general_purpose::STANDARD.encode(bytes)
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn run_challenge1() {
        // Cryptography generally deals with positive integers (unsigned).
        // In rust we can use u32, u64, u128 for unsigned integers but usually the numbers we use
        // when dealing with cryptography are much too large to fit into a regular integer so we
        // instead use byte arrays to store the number or hex or base64 strings when needing to encode data in a printable format
        // Numbers can be stored in byte arrays in big endian or little endian format
        // Big Endian Byte Order: The most significant byte (the "big end") of the data is placed at
        // the byte with the lowest address. The rest of the data is placed in order in the next three bytes in memory.
        // Little Endian Byte Order: The least significant byte (the "little end") of the data is
        // placed at the byte with the lowest address. The rest of the data is placed in order in the next three bytes in memory.

        let input_hex = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
        let input_base64 = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";

        let result_str = String::from_utf8(hex_to_bytes(input_hex)).unwrap();
        println!("{}", result_str);

        // convert hex to base64
        let result_base64 = bytes_to_base64(&hex_to_bytes(input_hex));
        assert_eq!(input_base64, result_base64);

        // convert base64 to hex
        let result_hex = bytes_to_hex(&base64_to_bytes(input_base64));
        assert_eq!(input_hex, result_hex)
    }

}