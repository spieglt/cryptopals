/*

Detect AES in ECB mode

In this file are a bunch of hex-encoded ciphertexts.

One of them has been encrypted with ECB.

Detect it.

Remember that the problem with ECB is that it is stateless and deterministic; the same 16 byte plaintext block will always produce the same 16 byte ciphertext.

*/

// one of them is encrypted. problem with ecb is 16 + key = 16. how would it not? how would any of these strings not map to the same thing when encrypted with the same key?
// why is it relevant that the same plaintext will produce the same ciphertext unless multiple blocks are the same? and decrypt with what key?
// something must be repeated.

use std::collections::HashSet;

pub fn detect_aes128ecb(text: &[u8]) -> bool {
	let mut seen = HashSet::new();
	let num_chunks = text.len() / 16;
	for c in 0..num_chunks {
		let current_chunk = text[c*16..(c+1)*16].to_vec();
		if seen.contains(&current_chunk) {
			// println!("repeater: {:?}\n", current_chunk);
			return true
		}
		seen.insert(current_chunk);
	}
	false
}
