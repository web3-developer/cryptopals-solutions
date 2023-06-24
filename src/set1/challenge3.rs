use std::collections::HashMap;
use character_frequency::character_frequencies_with_n_threads;

use crate::set1::challenge1::hex_to_bytes;
use crate::set1::challenge2::fixed_xor;

// score text for probability of being english
// each letter frequency is equal to the letter count / text.len
// expect letter frequency are defined on the internet
// score = sum of each abs(letter freq - expected freq


pub fn score_text_by_character_frequency(text: &str) -> f64 {
    let expected_freq = HashMap::from([
        ('e', 0.127),
        ('t', 0.091),
        ('a', 0.082),
        ('o', 0.075),
        ('i', 0.07),
        ('n', 0.067),
        //(" ", ),
        ('s', 0.063),
        ('h', 0.061),
        ('r', 0.06),
        ('d', 0.043),
        ('l', 0.04),
        ('u', 0.028),
    ]);

    let common_chars = "etaoinshrdlu";
    //let common_chars = "etaoin ";
    let counts = character_frequencies_with_n_threads(text, 1);

    let mut total_score: f64 = 0f64;
    for c in common_chars.chars() {
        //println!("{}", c);
        //println!("{}", counts.get(&c).unwrap_or(&0));
        let char_count = counts.get(&c).unwrap_or(&0);
        let char_freq = *char_count as f64 / text.len() as f64;
        let expected = expected_freq.get(&c).unwrap_or(&0f64);
        total_score += (char_freq - expected).abs();
    }

    total_score
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

                let score = score_text_by_character_frequency(&value);
                // find the min score
                // then find the key
                // show the decrypted message
                // try running it without the brute force method

                if score < 0.5 {
                    println!("key = {:?}", key);
                    println!("key = {}", std::str::from_utf8(&key).unwrap());
                    println!("value = {}", value);
                    println!("score = {}", score_text_by_character_frequency(&value));
                }
            }
        }

        //assert_eq!(expected, result)
    }

}