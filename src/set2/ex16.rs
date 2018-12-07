/*

CBC bitflipping attacks

Generate a random AES key.

Combine your padding code and CBC code to write two functions.

The first function should take an arbitrary input string, prepend the string:

"comment1=cooking%20MCs;userdata="

.. and append the string:

";comment2=%20like%20a%20pound%20of%20bacon"

The function should quote out the ";" and "=" characters.

The function should then pad out the input to the 16-byte AES block length and encrypt it under the random AES key.

The second function should decrypt the string and look for the characters ";admin=true;" (or, equivalently, decrypt, split the string on ";", convert each resulting string into 2-tuples, and look for the "admin" tuple).

Return true or false based on whether the string exists.

If you've written the first function properly, it should not be possible to provide user input to it that will generate the string the second function is looking for. We'll have to break the crypto to do that.

Instead, modify the ciphertext (without knowledge of the AES key) to accomplish this.

You're relying on the fact that in CBC mode, a 1-bit error in a ciphertext block:

    Completely scrambles the block the error occurs in
    Produces the identical 1-bit error(/edit) in the next ciphertext block.

Stop and think for a second.

Before you implement this attack, answer this question: why does CBC mode have this property?

*/

// "Note that a one-bit change to the ciphertext causes complete corruption of the corresponding block of plaintext,
// and inverts the corresponding bit in the following block of plaintext, but the rest of the blocks remain intact."

// they are all scrambled, but the bit that changes in CIPHERTEXT A will be the same bit that changes in the next block of PLAINTEXT B.
// so: encrypt version without equal sign, look one block back, flip necessary bit, decrypt that, check for change?

use crate::set2::{ex9, ex10, ex15};
use crate::utils;
use rand::{thread_rng, Rng};

pub fn assemble_and_encrypt(inp: &mut Vec<u8>, key: Vec<u8>, iv: &[u8; 16]) -> Vec<u8> {
	let mut escaped_input = vec![];
	inp.into_iter().for_each(|x| {
		escaped_input.append(&mut match x {
			b';' => "%3B".as_bytes().to_vec(),
			b'=' => "%3D".as_bytes().to_vec(),
			_ => vec![x.clone()],
		});
	});
	let (mut prefix, mut suffix) = (
		"comment1=cooking%20MCs;userdata=".as_bytes().to_vec(),
		";comment2=%20like%20a%20pound%20of%20bacon".as_bytes().to_vec()
	);
	prefix.append(&mut escaped_input);
	prefix.append(&mut suffix);
	println!("assembled plaintext:");
	utils::print_invalid_string(&prefix);

	let padded_bytes = ex9::pkcs7_padding(prefix.as_slice(), 16);
	ex10::encrypt_aes128cbc(&padded_bytes, &key, iv)
}

pub fn is_encrypted_admin(ciphertext: &mut Vec<u8>, key: &[u8], iv: &[u8; 16]) -> Result<bool, String> {
	match ex10::decrypt_aes128cbc(ciphertext, key, iv) {
		Ok(_) => (),
		Err(e) => return Err(format!("{:?}", e)),
	};
	println!("decrypted modified:");
	utils::print_invalid_string(ciphertext);
	let unencrypted = ex15::strip_padding(ciphertext)?;
	let s = String::from_utf8_lossy(&unencrypted);
	Ok(s.contains(";admin=true;"))
}

pub fn bitflipping_attack() {
	let mut key = [0u8; 16];
	thread_rng().fill(&mut key);
	println!("key: {:02x?}", key);
	let iv = &[0; 16];
	let plaintext: Vec<char> = "AAAA:admin<true".to_string().chars().collect();
	let original_ct = assemble_and_encrypt(&mut plaintext.clone().iter().map(|x| *x as u8).collect(), key.to_vec(), iv);

	print!("unmodified:");
	for (i,v) in original_ct.iter().enumerate() {
		if i % 16 == 0 {
			println!();
		}
		print!("{:02x} ", v);
	}
	println!();

	// < sign is at index 43. 43 - 16 = 27. flip last bit of byte[26].
	// : at 37, so [20]
	let mut modified_ct = original_ct.clone();
	modified_ct[26] ^= 1;
	modified_ct[20] ^= 1;
	match is_encrypted_admin(&mut modified_ct, &key, iv) {
		Ok(b) => println!("is admin: {}", b),
		Err(e) => println!("couldn't decrypt: {}", e),
	};
}


