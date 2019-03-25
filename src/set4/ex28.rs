/*

Implement a SHA-1 keyed MAC

Find a SHA-1 implementation in the language you code in.
Don't cheat. It won't work.
Do not use the SHA-1 implementation your language already provides (for instance, don't use the "Digest" library in Ruby, or call OpenSSL; in Ruby, you'd want a pure-Ruby SHA-1).

Write a function to authenticate a message under a secret key by using a secret-prefix MAC, which is simply:

SHA1(key || message)

Verify that you cannot tamper with the message without breaking the MAC you've produced, and that you can't produce a new MAC without knowing the secret key.

*/

use rand::{Rng, thread_rng};
use sha1::{Sha1, Digest};

struct Sha1KeyedMac {
	key: Vec<u8>
}

impl Sha1KeyedMac {
	pub fn new(key: &Vec<u8>) -> Sha1KeyedMac {
		Sha1KeyedMac{
			key: key.clone()
		}
	}

	pub fn gen(&self, message: &Vec<u8>) -> Vec<u8> {
		let mut inp = self.key.clone();
		inp.append(&mut message.clone());

		let mut hasher = Sha1::new();
		hasher.input(inp);
		hasher.result().to_vec()
	}

	pub fn authenticate(&self, mac: &Vec<u8>, message: &Vec<u8>) -> bool {
		self.gen(message) == *mac
	}
}

pub fn sha1_keyed_mac() {
	let key = (0..16).map(|_| thread_rng().gen::<u8>()).collect();
	let s1km = Sha1KeyedMac::new(&key);
	let message = &b"very important data indeed".to_vec();
	let mac = s1km.gen(message);

	assert!(s1km.authenticate(&mac, message));
	// Verify that you cannot tamper with the message without breaking the MAC you've produced
	assert!(!s1km.authenticate(&mac, &b"not so important data".to_vec()));
	// and that you can't produce a new MAC without knowing the secret key.
	let different_s1km = Sha1KeyedMac::new(&(0..16).map(|_| thread_rng().gen::<u8>()).collect());
	assert!(mac != different_s1km.gen(message));
	println!("authenticate function works");
}
