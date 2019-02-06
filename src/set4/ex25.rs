/*

Break "random access read/write" AES CTR

Back to CTR. Encrypt the recovered plaintext from this file (the ECB exercise) under CTR with a random key (for this exercise the key should be unknown to you, but hold on to it).

Now, write the code that allows you to "seek" into the ciphertext, decrypt, and re-encrypt with different plaintext. Expose this as a function, like, "edit(ciphertext, key, offset, newtext)".

Imagine the "edit" function was exposed to attackers by means of an API call that didn't reveal the key or the original plaintext; the attacker has the ciphertext and controls the offset and "new text".

Recover the original plaintext.
Food for thought.

A folkloric supposed benefit of CTR mode is the ability to easily "seek forward" into the ciphertext; to access byte N of the ciphertext, all you need to be able to do is generate byte N of the keystream. Imagine if you'd relied on that advice to, say, encrypt a disk.

*/

use crate::{ex11, ex18};
use crate::utils;
use rand::{thread_rng, Rng};

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
	fn edit(ciphertext: Vec<u8>, key: Vec<u8>, offset: u64, newtext: Vec<u8>) {
		// calculate block # of offset and # of blocks covered.
	}
}

pub fn break_random_access_read_write() {
	let plaintext = utils::read_file("./src/resources/ex25.txt");
	
	let key = ex11::gen_aes128_key().to_vec();
	let mut _nonce = [0u8; 8];
	thread_rng().fill(&mut _nonce);
	let nonce = _nonce.to_vec();

	let encrypter = CtrEncrypter::new(&key, &nonce);
	let encrypted = ex18::encrypt_ctr(&plaintext, &key, &nonce);

	
}