
use crate::set1::challenge1::hex_to_bytes;
use crate::set1::challenge2::fixed_xor;

pub fn repeat_key(in_key: &[u8], out_key: &mut [u8]) {
    if in_key.is_empty() {
        panic!("in_key cannot be empty");
    }

    let mut idx = 0;
    out_key.fill_with( || {
        let value = in_key[idx % in_key.len()];
        idx += 1;
        value
    } );
}


#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn run_challenge5() {
        let input_plaintext = "Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal".as_bytes();
        let expected_ciphertext = hex_to_bytes("0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f");

        let key = "ICE".as_bytes();
        let mut repeating_key = vec![0u8; input_plaintext.len()];
        repeat_key(key, &mut repeating_key);
        //println!("{:?}", &repeating_key);

        let result_ciphertext = fixed_xor(&repeating_key, input_plaintext);
        assert_eq!(expected_ciphertext, result_ciphertext);
    }

}