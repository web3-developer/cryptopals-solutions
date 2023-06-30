
use base64_light::{base64_encode_bytes, base64_decode};


pub fn bytes_to_hex(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

pub fn hex_to_bytes(hex: &str) -> Vec<u8> {
    hex::decode(hex).unwrap()
}

pub fn bytes_to_base64(bytes: &[u8]) -> String {
    base64_encode_bytes(bytes)
}

pub fn base64_to_bytes(base64: &str) -> Vec<u8> {
    base64_decode(base64)
}


#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn run_challenge1() {
        let input_hex = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
        let input_base64 = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";

        let result_str = String::from_utf8(hex_to_bytes(input_hex)).unwrap();
        println!("{}", result_str);
        assert_eq!("I'm killing your brain like a poisonous mushroom", result_str);

        // convert hex to base64
        let result_base64 = bytes_to_base64(&hex_to_bytes(input_hex));
        assert_eq!(input_base64, result_base64);

        // convert base64 to hex
        let result_hex = bytes_to_hex(&base64_to_bytes(input_base64));
        assert_eq!(input_hex, result_hex)
    }

}