/*

Convert hex to base64

The string:

49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d

Should produce:

SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t

So go ahead and make that happen. You'll need to use this code for the rest of the exercises.
Cryptopals Rule

Always operate on raw bytes, never on encoded strings. Only use hex and base64 for pretty-printing.

*/

pub fn bytes_to_base64(inp: Vec<u8>) -> Vec<char> {

	let key: Vec<char> = "ABCDEFGHIJKLMNOPQRSTUVWXYZ\
		abcdefghijklmnopqrstuvwxyz\
		0123456789+/".chars().collect();

	let mut bytes: Vec<usize> = Vec::new();
	for d in inp.into_iter() {
		bytes.push(d as usize);
	}

	let mut output: Vec<char> = vec![];

	for i in 0..bytes.len() {
		if i % 3 == 0 {
			// if next 2, grab 3
			if i + 2 < bytes.len() {
				let first = bytes[i] >> 2;
				let mut second = (bytes[i] & ((1 << 2) - 1)) << 4;
				second += bytes[i+1] >> 4;
				let mut third = (bytes[i+1] & ((1 << 4) - 1)) << 2;
				third += bytes[i+2] >> 6;
				let fourth = bytes[i+2] & ((1 << 6) - 1);
				output.push(key[first]);
				output.push(key[second]);
				output.push(key[third]);
				output.push(key[fourth]);
			} else if i + 2 == bytes.len() {
				let first = bytes[i] >> 2;
				let mut second = (bytes[i] & ((1 << 2) - 1)) << 4;
				second += bytes[i+1] >> 4;
				let third = (bytes[i+1] & ((1 << 4) - 1)) << 2;
				output.push(key[first]);
				output.push(key[second]);
				output.push(key[third]);
				output.push('=');
			} else {
				let first = bytes[i] >> 2;
				let second = (bytes[i] & ((1 << 2) - 1)) << 4;
				output.push(key[first]);
				output.push(key[second]);
				output.push('=');
				output.push('=');
			}
		}
	}

	output
}
