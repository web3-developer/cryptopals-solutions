
use openssl::error::ErrorStack;
use openssl::symm::{Cipher, Crypter, Mode};
use openssl::symm::Mode::{Decrypt, Encrypt};

use crate::set1::challenge2::fixed_xor;
use crate::set2::challenge9::pad_using_pkcs7;

const BLOCK_SIZE_BYTES: usize = 16;

fn cipher(
    t: Cipher,
    mode: Mode,
    key: &[u8],
    iv: Option<&[u8]>,
    data: &[u8],
) -> Result<Vec<u8>, ErrorStack> {
    let mut c = Crypter::new(t, mode, key, iv)?;
    c.pad(false); // disable padding as we are only using this to encrypt/decrypt single block at a time
    let mut out = vec![0; data.len() + t.block_size()];
    let count = c.update(data, &mut out)?;
    let rest = c.finalize(&mut out[count..])?;
    out.truncate(count + rest);
    Ok(out)
}

pub fn aes_128_ecb_encrypt_no_padding(key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, ErrorStack> {
    cipher(Cipher::aes_128_ecb(), Encrypt, key, None, plaintext)
}

pub fn aes_128_ecb_decrypt_no_padding(key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, ErrorStack> {
    cipher(Cipher::aes_128_ecb(), Decrypt, key, None, ciphertext)
}

pub fn aes_128_cbc_encrypt(key: &[u8], iv: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, ErrorStack>
{
    if key.len() != BLOCK_SIZE_BYTES || iv.len() != BLOCK_SIZE_BYTES {
        panic!("key and iv must be equal to the block size");
    }

    let padded_plaintext = pad_using_pkcs7(BLOCK_SIZE_BYTES as u8, plaintext);
    let plaintext_blocks: Vec<&[u8]> = padded_plaintext.chunks(BLOCK_SIZE_BYTES).collect();

    let mut ciphertext = Vec::with_capacity(padded_plaintext.len());
    let mut next_iv = iv.to_vec();

    for block in plaintext_blocks {
        let mut ciphertext_block = aes_128_ecb_encrypt_no_padding(key, &fixed_xor(&next_iv, block))?;
        next_iv = ciphertext_block.clone();
        ciphertext.append(&mut ciphertext_block);
    }

    Ok(ciphertext)
}

pub fn aes_128_cbc_decrypt(key: &[u8], iv: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, ErrorStack>
{
    if key.len() != BLOCK_SIZE_BYTES || iv.len() != BLOCK_SIZE_BYTES {
        panic!("key and iv must be equal to the block size");
    }

    let ciphertext_blocks: Vec<&[u8]> = ciphertext.chunks(BLOCK_SIZE_BYTES).collect();
    let mut plaintext = Vec::with_capacity(ciphertext_blocks.len());
    let mut next_iv = iv.to_vec();

    for block in ciphertext_blocks {
        let mut plaintext_block = fixed_xor(&next_iv, &aes_128_ecb_decrypt_no_padding(key, &block)?);
        next_iv = block.to_vec();
        plaintext.append(&mut plaintext_block);
    }

    // remove padding assuming PKCS#7 format
    let num_padding_bytes = plaintext[plaintext.len() - 1]; // get the number of padding bytes from the last byte
    plaintext.truncate(plaintext.len() - num_padding_bytes as usize);

    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use crate::set1::challenge1::base64_to_bytes;
    use super::*;


    #[test]
    fn test_ecb_encrypt_decrypt() {
        let key = "YELLOW SUBMARINE".as_bytes();
        let input_plaintext = "1234123412341234".as_bytes(); // 16 bytes, one block

        let ciphertext = aes_128_ecb_encrypt_no_padding(key, input_plaintext).unwrap();
        let result = aes_128_ecb_decrypt_no_padding(key, &ciphertext).unwrap();

        assert_eq!(input_plaintext, result);
    }

    #[test]
    fn test_cbc_encrypt_decrypt() {
        let key = "YELLOW SUBMARINE".as_bytes();
        let iv = vec![0u8; BLOCK_SIZE_BYTES];
        let input_plaintext = "123412341234123412".as_bytes();

        let ciphertext = aes_128_cbc_encrypt(key, &iv, input_plaintext).unwrap();
        let result = aes_128_cbc_decrypt(key, &iv, &ciphertext).unwrap();

        assert_eq!(input_plaintext, result);
    }

    #[test]
    fn run_challenge10() {
        let input_ciphertext = base64_to_bytes("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");

        let key = "YELLOW SUBMARINE".as_bytes();
        let iv = vec![0u8; BLOCK_SIZE_BYTES];

        let result = aes_128_cbc_decrypt(key, &iv, &input_ciphertext).unwrap();
        let plaintext = String::from_utf8(result).unwrap();
        println!("plaintext = {}", plaintext);

        assert!(plaintext.starts_with("I'm back and I'm ringin' the bell \n"));
    }

}