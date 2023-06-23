
use character_frequency::character_frequencies_with_n_threads;

use crate::set1::challenge1::hex_to_bytes;
use crate::set1::challenge2::fixed_xor;


pub fn sum_common_characters(text: &str) -> usize {
    //let common_chars = "etaoin shrdlu";
    let common_chars = "etaoin ";
    let counts = character_frequencies_with_n_threads(text, 1);

    let mut total_count: usize = 0;
    for c in common_chars.chars() {
        //println!("{}", c);
        //println!("{}", counts.get(&c).unwrap_or(&0));
        total_count += counts.get(&c).unwrap_or(&0);
    }

    total_count
}


#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn run_challenge3() {
        let input1 = hex_to_bytes("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736");

        // 256 possible keys
        // try brute force attack by decrypting with each key and checking for a valid message
        for i in 0u8..=255 {
            // create a key stream of equal length
            let key = vec![i; input1.len()];

            let result = fixed_xor(&input1, &key);
            let result_str = std::str::from_utf8(&result);

            if let Ok(value) = result_str {
                // ignore the values that don't parse as text

                let count = sum_common_characters(&value);
                if count > 10 {
                    println!("key = {:?}", key);
                    println!("key = {}", std::str::from_utf8(&key).unwrap());
                    println!("value = {}", value);
                    println!("common chars count = {}", sum_common_characters(&value));
                }
            }
        }

        //assert_eq!(expected, result)
    }

}