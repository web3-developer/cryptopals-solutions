
use crate::set1::challenge1::hex_to_bytes;


pub fn fixed_xor(x: &[u8], y: &[u8]) -> Vec<u8> {
    if x.len() != y.len() {
        panic!("x and y are not equal length");
    }

    let mut result = Vec::with_capacity(x.len());
    for i in 0..x.len() {
        result.push(x[i] ^ y[i])
    }

    result
}


#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn run_challenge2() {
        let input1 = hex_to_bytes("1c0111001f010100061a024b53535009181c");
        let input2 = hex_to_bytes("686974207468652062756c6c277320657965");
        let expected = hex_to_bytes("746865206b696420646f6e277420706c6179");

        let result = fixed_xor(&input1, &input2);
        assert_eq!(expected, result);

        let result_str = String::from_utf8(result).unwrap();
        println!("{}", result_str);
    }

}