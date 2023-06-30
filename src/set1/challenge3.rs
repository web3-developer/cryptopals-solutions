use std::collections::HashMap;
use character_frequency::{CaseSense, character_frequencies_w_case};

use crate::set1::challenge1::hex_to_bytes;
use crate::set1::challenge2::fixed_xor;

// Score text for probability of being english.
// Each letter frequency is equal to the letter count / text.len.
// Expected letter frequency are defined on the internet.
// score = sum of each abs(expected freq - letter freq)
pub fn score_text_by_character_frequency(text: &str) -> f64 {
    let expected_freq = HashMap::from([
        ('e', 0.127),
        ('t', 0.091),
        ('a', 0.082),
        ('o', 0.075),
        ('i', 0.07),
        ('n', 0.067),
        ('s', 0.063),
        ('h', 0.061),
        ('r', 0.06),
        ('d', 0.043),
        ('l', 0.04),
        ('u', 0.028),
    ]);

    let common_chars = "etaoinshrdlu";
    let counts = character_frequencies_w_case(text, CaseSense::Sensitive);

    let mut total_score: f64 = 0f64;
    for c in common_chars.chars() {
        let char_count = counts.get(&c).unwrap_or(&0);
        //println!("char_count = {}", char_count);
        let char_freq = *char_count as f64 / text.len() as f64;
        //println!("char_freq = {}", char_freq);
        let expected = expected_freq.get(&c).unwrap_or(&0f64);
        //println!("expected = {}", expected);
        total_score += (expected - char_freq).abs();
    }

    total_score
}

// Finds the best text candidate for the given ciphertext assuming usage of a single character key
pub fn single_char_xor_find_best_candidate(ciphertext: &[u8]) -> (f64, u8, String) {
    // There are 256 possible keys.
    // Try brute force attack by decrypting with each key and checking for a valid message.
    let mut best_candidate: (f64, u8, String) = (1f64, 0, "".to_owned());
    for i in 0u8..=255 {
        // create a key stream of equal length
        let key = vec![i; ciphertext.len()];

        let result = fixed_xor(&ciphertext, &key);
        let result_str = String::from_utf8(result);

        if let Ok(value) = result_str { // ignore the values that don't parse as text

            let score = score_text_by_character_frequency(&value);
            if score < best_candidate.0 {
                best_candidate = (score, key[0], value);
            }
        }
    }

    best_candidate
}


#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn run_challenge3() {
        let ciphertext = hex_to_bytes("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736");
        let best_candidate = single_char_xor_find_best_candidate(&ciphertext);
        assert_eq!("Cooking MC's like a pound of bacon", best_candidate.2);

        println!("Best candidate score = {}", best_candidate.0);
        println!("Best candidate key = {}", best_candidate.1 as char);
        println!("Best candidate text = {}", best_candidate.2);
    }

}