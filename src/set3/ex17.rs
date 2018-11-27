/*

The CBC padding oracle

This is the best-known attack on modern block-cipher cryptography.

Combine your padding code and your CBC code to write two functions.

The first function should select at random one of the following 10 strings:

MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=
MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=
MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==
MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==
MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl
MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==
MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==
MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=
MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=
MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93

... generate a random AES key (which it should save for all future encryptions), pad the string out to the 16-byte AES block size and CBC-encrypt it under that key, providing the caller the ciphertext and IV.

The second function should consume the ciphertext produced by the first function, decrypt it, check its padding, and return true or false depending on whether the padding is valid.
What you're doing here.

This pair of functions approximates AES-CBC encryption as its deployed serverside in web applications; the second function models the server's consumption of an encrypted session token, as if it was a cookie.

It turns out that it's possible to decrypt the ciphertexts provided by the first function.

The decryption here depends on a side-channel leak by the decryption function. The leak is the error message that the padding is valid or not.

You can find 100 web pages on how this attack works, so I won't re-explain it. What I'll say is this:

The fundamental insight behind this attack is that the byte 01h is valid padding, and occur in 1/256 trials of "randomized" plaintexts produced by decrypting a tampered ciphertext.

02h in isolation is not valid padding.

02h 02h is valid padding, but is much less likely to occur randomly than 01h.

03h 03h 03h is even less likely.

So you can assume that if you corrupt a decryption AND it had valid padding, you know what that padding byte is.

It is easy to get tripped up on the fact that CBC plaintexts are "padded". Padding oracles have nothing to do with the actual padding on a CBC plaintext. It's an attack that targets a specific bit of code that handles decryption. You can mount a padding oracle on any CBC block, whether it's padded or not.

*/

// two problems to solve:
// 1. how to know that first byte padding is valid because it's 0x1 and not because it ends in 0x4, 0x4, 0x4, 0x4?
//		if unmodified, presumably it would have valid padding, so making sure that i != last byte takes care of this.
// 2. what to do if padding not found? panic.

use ex9;
use ex10;
use ex15;
use utils;
use rand::{thread_rng, Rng};

fn encrypt_random_string(key: &[u8]) -> (Vec<u8>, [u8; 16]) {
	let b64_strings = [
		"MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
		"MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
		"MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
		"MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
		"MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
		"MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
		"MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
		"MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
		"MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
		"MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93",
	];
	let byte_vecs: Vec<Vec<u8>> = b64_strings.into_iter().map(
		|x| utils::base64_to_bytes(&x.to_string())
	).collect();
	
	// pick random byte vec, encrypt and return with iv

	let mut iv = [0u8; 16];
	thread_rng().fill(&mut iv);
	println!("iv: {:02x?}", iv);
	let i: usize = thread_rng().gen_range(0,byte_vecs.len());
	let selected_string = &byte_vecs[i];
	println!("{}", String::from_utf8_lossy(selected_string));
	let padded_string = ex9::pkcs7_padding(&selected_string, 16);
	(ex10::encrypt_aes128cbc(&padded_string, key, &iv), iv)
}

fn padding_is_valid(ciphertext: &mut Vec<u8>, key: &[u8], iv: &[u8]) -> bool {
	ex10::decrypt_aes128cbc(ciphertext, key, iv).expect("couldn't decrypt with cbc");
	match ex15::strip_padding(ciphertext) {
		Ok(_) => true,
		Err(_) => false,
	}
}

pub fn cbc_padding_oracle() {

	let mut key = [0u8; 16];
	thread_rng().fill(&mut key);

	let (ciphertext, iv) = encrypt_random_string(&key);
	println!("ciphertext:\n{:02x?}", ciphertext);

	// the point is to force last byte to be 0x1, xor hot byte with 0x1 and then we have last byte.
	// next we, knowing last byte, force it to be 0x2, then next to last to be 0x2 by looping again...

	let mut real_bytes = vec![];
	// for each block
	for block_num in (0..ciphertext.len() / 16).rev() {
		println!("\non block {}", block_num);
		let mut padding_producing_bytes = vec![];
		// for each byte of the block
		for byte_num in 0..16 {
			let mut current_block = ciphertext[block_num*16..(block_num+1)*16].to_vec();
			let mut previous_block = match block_num {
				0 => iv.to_vec(),
				_ => ciphertext[(block_num-1)*16..block_num*16].to_vec(),
			};
			let byte_to_be_tested = previous_block.len() - 1 - byte_num;
			let target_padding_digit = byte_num as u8 + 1;
			// force last temp bytes len to be 0xIndex + 1
			for ppb in 0..padding_producing_bytes.len() {
				let l = current_block.len();
				previous_block[l - 1 - ppb] = padding_producing_bytes[ppb] ^ target_padding_digit;
			}
			// solve current byte with byte of prev block to be 0xIndex + 1
			let mut padding_found = false;
			// for each possible value of the byte
			for i in 0..=255 {
				let mut the_rest = match block_num {
					0 | 1	=> vec![],
					_		=> ciphertext[..(block_num-1)*16].to_vec()
				};
				let mut pb = previous_block.clone();
				// skip i if on first byte because it will have valid padding when decrypted
				// we want to force it to be 0x1 when decrypted. but what if it would've been anyway?
				if byte_num == 0 && i == pb[byte_to_be_tested] {
					continue
				} else {
					pb[byte_to_be_tested] = i;
				}
			
				the_rest.append(&mut pb);
				the_rest.append(&mut current_block.clone());
				// if byte_num == 0 && i == 0 { println!("the_rest:\n{:02x?}", the_rest) };

				if padding_is_valid(&mut the_rest, &key, &iv) {
					padding_found = true;
					padding_producing_bytes.push(i ^ target_padding_digit);
					real_bytes.insert(0, (i ^ target_padding_digit) ^ previous_block[byte_to_be_tested]);					
					break;
				}
			}
			
			if !padding_found { panic!("padding not found"); }
		}
	}
	let res = ex15::strip_padding(&real_bytes).expect("invalid padding on decrypted string");
	println!("result: {}", String::from_utf8_lossy(&res));
	println!("result: {:02x?}", res);
}

