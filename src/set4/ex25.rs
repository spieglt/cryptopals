/*

Break "random access read/write" AES CTR

Back to CTR. Encrypt the recovered plaintext from this file (the ECB exercise) under CTR with a random key (for this exercise the key should be unknown to you, but hold on to it).

Now, write the code that allows you to "seek" into the ciphertext, decrypt, and re-encrypt with different plaintext. Expose this as a function, like, "edit(ciphertext, key, offset, newtext)".

Imagine the "edit" function was exposed to attackers by means of an API call that didn't reveal the key or the original plaintext; the attacker has the ciphertext and controls the offset and "new text".

Recover the original plaintext.
Food for thought.

A folkloric supposed benefit of CTR mode is the ability to easily "seek forward" into the ciphertext; to access byte N of the ciphertext, all you need to be able to do is generate byte N of the keystream. Imagine if you'd relied on that advice to, say, encrypt a disk.

*/

use crate::{ex7, ex10, ex11, ex18};
use crate::utils;
use rand::{thread_rng, Rng};
use std::io;
use std::io::Write;
use std::mem::transmute;

// attacker controls offset and new text. ciphertext is xor of plaintext and keystream. keystream is aes of key and nonce + counter. we know counter.
// we don't know nonce but we do because we who are writing the edit function have the key, we're just exposing the function. so we have key.
// attacker wants to recover original plaintext, which means they need keystream. they can... adjust last byte to valid padding? no, not that attack.
// but can do with all 0, see what it produces, and compare to known? no.

// edit entire first block - 1 with 0, note ciphertext. then edit entire first block - 1 with 0, loop through other values of byte, and compare to ciphertext.

struct CtrEncrypter {
	key: Vec<u8>,
	nonce: Vec<u8>,
}

impl CtrEncrypter {
	fn new(key: &Vec<u8>, nonce: &Vec<u8>) -> CtrEncrypter {
		CtrEncrypter{key: key.clone(), nonce: nonce.clone()}
	}
	fn edit(&self, ciphertext: &Vec<u8>, offset: usize, newtext: &Vec<u8>) -> Vec<u8> {
		assert!(offset + newtext.len() < ciphertext.len());
		let block_size = 16;
		let low_block = offset / block_size;
		let high_block = (offset + newtext.len()) / block_size;
		let num_blocks = 1 + high_block - low_block;
		// need keystream for those blocks, so need nonce and to transmute block nums, then aes with key
		let mut keystream: Vec<u8> = vec![];
		for block_num in low_block..=high_block {
			let bytes: [u8; 8] = unsafe { transmute(block_num.to_le()) };
			let mut bv = bytes.to_vec();
			let mut material = &mut self.nonce.clone();
			material.append(&mut bv);
			ex10::encrypt_aes128ecb(&mut material, &self.key).expect("couldn't encrypt with ecb");
			keystream.append(material);
		}
		// then grab those blocks from ciphertext, xor, edit, re-xor, put back into ciphertext
		let mut text_to_edit = ciphertext[low_block*block_size..
				utils::min(ciphertext.len(), (low_block+num_blocks)*block_size) // don't reach past end of ciphertext
			].to_vec();
		for i in 0..text_to_edit.len() {
			text_to_edit[i] = text_to_edit[i] ^ keystream[i];
		}
		// text_to_edit is now in plaintext form, time to edit
		let local_offset = offset % block_size;
		for (i, b) in newtext.iter().enumerate() {
			text_to_edit[local_offset + i] = *b;
		}
		// re-xor with keystream
		for i in 0..text_to_edit.len() {
			text_to_edit[i] = text_to_edit[i] ^ keystream[i];
		}
		// reconstruct ciphertext
		let mut new_ciphertext = ciphertext[..block_size*low_block].to_vec();
		new_ciphertext.append(&mut text_to_edit);
		let mut original_end = ciphertext[utils::min(ciphertext.len(), block_size*(high_block+1))..].to_vec();
		new_ciphertext.append(&mut original_end);
		new_ciphertext
	}
}

pub fn break_random_access_read_write() {
	let block_size = 16;

	let plaintext_b64 = String::from_utf8(utils::read_file("./src/resources/25.txt")).expect("could not convert to string");
	let mut plaintext = utils::base64_to_bytes(&plaintext_b64);

	// misread the prompt. thought "the recovered plaintext from this file (the ECB exercise)" meant recovered by base64-decoding,
	// but in ex7, the ecb exercise, this was still encrypted after decoding. so we need to ecb decrypt it.
	ex7::decrypt_aes128ecb(&mut plaintext, "YELLOW SUBMARINE".as_bytes()).expect("could not decrypt");
	
	let key = ex11::gen_aes128_key().to_vec();
	let mut _nonce = [0u8; 8];
	thread_rng().fill(&mut _nonce);
	let nonce = _nonce.to_vec();

	let encrypter = CtrEncrypter::new(&key, &nonce);
	let encrypted = ex18::encrypt_ctr(&plaintext, &key, &nonce);

	let mut known_bytes = Vec::new();
	let mut bytes_left = encrypted.len();
	// for each block
	for i in 0..utils::ceil(encrypted.len(), block_size) {
		
		let lower_bound = i*block_size;
		let upper_bound = i*block_size + utils::min(block_size, bytes_left);
		// println!("lower bound = {}, upper bound = {}", lower_bound, upper_bound);

		// for each byte of block
		for test_byte_index in 0..(upper_bound - lower_bound) {
			let reference_ct = encrypter.edit(&mut encrypted.clone(), lower_bound + test_byte_index + 1, &vec![b'0'; block_size-1-test_byte_index]);

			// for all possible values
			for b in 0..=255 {
				let mut test_data = vec![b];
				test_data.append(&mut vec![b'0'; block_size-1-test_byte_index]);
				let test_ct = encrypter.edit(&mut encrypted.clone(), lower_bound + test_byte_index, &test_data);
				if test_ct == reference_ct {
					print!("{}", b as char);
					io::stdout().flush().expect("could not flush stdout");
					known_bytes.push(b);
					break;
				}
			}
		}
		bytes_left -= upper_bound - lower_bound
	}
	// println!("{}", String::from_utf8_lossy(&known_bytes));
}

mod tests {
	#[test]
	fn test_edit() {
		use crate::{ex11, ex18};
		use rand::{Rng, thread_rng};
		
		let plaintext = "HEY THERE THIS HERE'S THE TEXT WE'RE GONNA ENCRYPT".as_bytes().to_vec();

		let key = ex11::gen_aes128_key().to_vec();
		let mut _nonce = [0u8; 8];
		thread_rng().fill(&mut _nonce);
		let nonce = _nonce.to_vec();
		let encrypter = super::CtrEncrypter::new(&key, &nonce);

		let encrypted = ex18::encrypt_ctr(&plaintext, &key, &nonce);
		let edited = encrypter.edit(&encrypted, 4, &"what's up".bytes().collect());

		let unencrypted = ex18::encrypt_ctr(&edited, &key, &nonce);
		let res: Vec<u8> = "HEY what's upS HERE'S THE TEXT WE'RE GONNA ENCRYPT".bytes().collect();
		assert_eq!(unencrypted, res);
	}
}
