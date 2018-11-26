/*

PKCS#7 padding validation

Write a function that takes a plaintext, determines if it has valid PKCS#7 padding, and strips the padding off.

The string:

"ICE ICE BABY\x04\x04\x04\x04"

... has valid padding, and produces the result "ICE ICE BABY".

The string:

"ICE ICE BABY\x05\x05\x05\x05"

... does not have valid padding, nor does:

"ICE ICE BABY\x01\x02\x03\x04"

If you are writing in a language with exceptions, like Python or Ruby, make your function throw an exception on bad padding.

Crypto nerds know where we're going with this. Bear with us.

*/

pub fn strip_padding(plaintext: &Vec<u8>) -> Result<Vec<u8>, &str> {
	let pad_val = plaintext[plaintext.len() - 1];
	if pad_val == 0 {
		return Err("invalid padding")
	}
	for i in 0..pad_val {
		if plaintext[plaintext.len() - 1 - i as usize] != pad_val {
			return Err("invalid padding")
		}
	}
	Ok(plaintext[..plaintext.len() - pad_val as usize].to_vec())
}

#[cfg(test)]
mod tests {
	use ex15::strip_padding;
	use ex9;
	
	#[test]
	fn test_strip_padding() {
		for i in 0..32 {
			let mut inp = vec![b'A'; i];
			let padded = ex9::pkcs7_padding(inp.as_slice(), 16);
			let stripped = strip_padding(&padded).unwrap();
			assert!(inp == stripped);
		}
	}
}

