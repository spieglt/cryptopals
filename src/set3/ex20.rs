/*

Break fixed-nonce CTR statistically

In this file find a similar set of Base64'd plaintext. Do with them exactly what you did with the first, but solve the problem differently.

Instead of making spot guesses at to known plaintext, treat the collection of ciphertexts the same way you would repeating-key XOR.

Obviously, CTR encryption appears different from repeated-key XOR, but with a fixed nonce they are effectively the same thing.

To exploit this: take your collection of ciphertexts and truncate them to a common length (the length of the smallest ciphertext will work).

Solve the resulting concatenation of ciphertexts as if for repeating- key XOR, with a key size of the length of the ciphertext you XOR'd.

*/

use ex6;
use ex18;
use utils;
use rand::{Rng, thread_rng};

pub fn break_fixed_nonce_ctr_statistically() {

	let nonce = [0; 8].to_vec();
	let mut _key = [0; 16];
	thread_rng().fill(&mut _key);
	let key = _key.to_vec();

	let plaintext_lines = utils::b64_file_to_byte_lines("./src/resources/20.txt");
	let encrypted_lines: Vec<Vec<u8>> = plaintext_lines.iter().map(|pt| {
		ex18::encrypt_ctr(
			&pt,
			&key,
			&nonce
		)
	}).collect();

	let shortest_len = encrypted_lines.iter()
		.min_by_key(|line| line.len())
		.expect("could not take line lengths")
		.len();
	// println!("{:?}", shortest_len);

	let chopped_and_combined_lines: Vec<u8> = encrypted_lines.iter().map(|l| {
		l[..shortest_len].to_vec()
	}).flatten().collect();

	let (key, decrypted) = ex6::break_repeating_key_xor(&chopped_and_combined_lines, shortest_len);
	println!("key: {:02x?}\ndecrypted:", key);
	utils::print_invalid_string(&decrypted);
}

