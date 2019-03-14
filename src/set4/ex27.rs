/*

Recover the key from CBC with IV=Key

Take your code from the CBC exercise and modify it so that it repurposes the key for CBC encryption as the IV.

Applications sometimes use the key as an IV on the auspices that both the sender and the receiver have to know the key already, and can save some space by using it as both a key and an IV.

Using the key as an IV is insecure; an attacker that can modify ciphertext in flight can get the receiver to decrypt a value that will reveal the key.

The CBC code from exercise 16 encrypts a URL string. Verify each byte of the plaintext for ASCII compliance (ie, look for high-ASCII values). Noncompliant messages should raise an exception or return an error that includes the decrypted plaintext (this happens all the time in real systems, for what it's worth).

Use your code to encrypt a message that is at least 3 blocks long:

AES-CBC(P_1, P_2, P_3) -> C_1, C_2, C_3

Modify the message (you are now the attacker):

C_1, C_2, C_3 -> C_1, 0, C_1

Decrypt the message (you are now the receiver) and raise the appropriate error if high-ASCII is found.

As the attacker, recovering the plaintext from the error, extract the key:

P'_1 XOR P'_3

*/

use crate::{ex10, ex16};
use rand::{Rng, thread_rng};

fn assemble_and_encrypt(inp: &mut Vec<u8>, key: &[u8; 16]) -> Vec<u8> {
	ex16::assemble_and_encrypt(inp, key.to_vec(), key)
}

fn decrypt(mut inp: &mut Vec<u8>, key: &[u8]) -> Result<(), String> {
	match ex10::decrypt_aes128cbc(&mut inp, key, key) {
		Ok(()) => (),
		Err(x) => return Err("block mode error".to_string()),
	}
	for c in inp.iter() {
		match c.is_ascii() {
			true => (),
			false => return Err("non ascii char".to_string()),
		}
	}
	Ok(())
}

pub fn crack_cbc_key_equals_iv() {
	let key_size = 16;
	let mut key = [0u8; 16];
	thread_rng().fill(&mut key);
	// println!("key: {:02x?}", key);
	
	let plaintext: Vec<char> = "looooooooooooongboi, many blocks".to_string().chars().collect();
	let original_ct = assemble_and_encrypt(&mut plaintext.clone().iter().map(|x| *x as u8).collect(), &key);

	let mut modified_ct = original_ct[..key_size].to_vec();
	modified_ct.append(&mut [0;16].to_vec());
	let mut repeat = original_ct[..key_size].to_vec();
	modified_ct.append(&mut repeat);

	match decrypt(&mut modified_ct, &key) {
		Ok(()) => (),
		Err(e) => {
			println!("decryption error: {}", e);
			println!("plaintext: {:02x?}", modified_ct)
		}
	}

	let returned_plaintext = modified_ct;
	let p1 = returned_plaintext[..key_size].to_vec();
	let p3 = returned_plaintext[key_size*2..key_size*3].to_vec();
	let recovered_key: Vec<u8> = p1.iter().enumerate().map(|(i, c)| c ^ p3[i]).collect();
	// println!("recovered key: {:02x?}", recovered_key);
	println!("original key matches recovered: {}", key[..] == recovered_key[..]);
}
