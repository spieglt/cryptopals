/*

CTR bitflipping

There are people in the world that believe that CTR resists bit flipping attacks of the kind to which CBC mode is susceptible.

Re-implement the CBC bitflipping exercise from earlier to use CTR mode instead of CBC mode. Inject an "admin=true" token.

*/

use crate::{ex18, utils};
use rand::{Rng, thread_rng};

pub fn ctr_assemble_and_encrypt(inp: &mut Vec<u8>, key: &Vec<u8>, nonce: &Vec<u8>) -> Vec<u8> {
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

	ex18::encrypt_ctr(&prefix, &key, &nonce)
}

pub fn ctr_is_encrypted_admin(ciphertext: &Vec<u8>, key: &Vec<u8>, nonce: &Vec<u8>) -> bool {
	let decrypted = ex18::encrypt_ctr(ciphertext, key, nonce);
	let s = String::from_utf8_lossy(&decrypted);
	s.contains(";admin=true;")
}

pub fn ctr_bitflipping_attack() {
	let mut key = [0u8; 16];
	thread_rng().fill(&mut key);
	let mut nonce = [0u8; 8];
	thread_rng().fill(&mut nonce);
	
	let plaintext: Vec<char> = "AAAA:admin<true".to_string().chars().collect();
	let original_ct = ctr_assemble_and_encrypt(
		&mut plaintext.clone().iter().map(|x| *x as u8).collect(), 
		&key.to_vec(), &nonce.to_vec()
	);
	println!("original is admin: {}", ctr_is_encrypted_admin(&original_ct, &key.to_vec(), &nonce.to_vec()));

	let mut modified_ct = original_ct.clone();
	modified_ct[42] ^= 1;
	modified_ct[36] ^= 1;
	
	println!("modified is admin: {}", ctr_is_encrypted_admin(&modified_ct, &key.to_vec(), &nonce.to_vec()));
}
