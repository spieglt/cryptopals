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

fn edit() {

}

pub fn break_random_access_read_write() {
	let plaintext = utils::read_file("./src/resources/ex25.txt");
	let key = ex11::gen_aes128_key().to_vec();

	let mut _nonce = [0u8; 8];
	thread_rng().fill(&mut _nonce);
	let nonce = _nonce.to_vec();

	let encrypted = ex18::encrypt_ctr(&plaintext, &key, &nonce);
}