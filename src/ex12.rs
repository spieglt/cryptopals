/*

Byte-at-a-time ECB decryption (Simple)

Copy your oracle function to a new function that encrypts buffers under ECB mode using a consistent but unknown key (for instance, assign a single random key, once, to a global variable).

Now take that same function and have it append to the plaintext, BEFORE ENCRYPTING, the following string:

Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK

Spoiler alert.

Do not decode this string now. Don't do it.

Base64 decode the string before appending it. Do not base64 decode the string by hand; make your code do it. The point is that you don't know its contents.

What you have now is a function that produces:

AES-128-ECB(your-string || unknown-string, random-key)

It turns out: you can decrypt "unknown-string" with repeated calls to the oracle function!

Here's roughly how:

    Feed identical bytes of your-string to the function 1 at a time --- start with 1 byte ("A"), then "AA", then "AAA" and so on. Discover the block size of the cipher. You know it, but do this step anyway.
    Detect that the function is using ECB. You already know, but do this step anyways.
    Knowing the block size, craft an input block that is exactly 1 byte short (for instance, if the block size is 8 bytes, make "AAAAAAA"). Think about what the oracle function is going to put in that last byte position.
    Make a dictionary of every possible last byte by feeding different strings to the oracle; for instance, "AAAAAAAA", "AAAAAAAB", "AAAAAAAC", remembering the first block of each invocation.
    Match the output of the one-byte-short input to one of the entries in your dictionary. You've now discovered the first byte of unknown-string.
    Repeat for the next byte.

Congratulations.

This is the first challenge we've given you whose solution will break real crypto. Lots of people know that when you encrypt something in ECB mode, you can see penguins through it. Not so many of them can decrypt the contents of those ciphertexts, and now you can. If our experience is any guideline, this attack will get you code execution in security tests about once a year.

*/

use ex8;
use ex9;
use ex10;
use ex11;
use utils;
use std::collections::HashMap;

pub struct SingleKeyEncrypter {
	pub key: [u8; 16]
}

// pub trait EncryptAes128Ecb {
// 	fn encrypt_aes128ecb(&self, &mut Vec<u8>) -> Vec<u8>;
// }

// does not encrypt in place
impl /*EncryptAes128Ecb for*/ SingleKeyEncrypter {
	pub fn encrypt_aes128ecb(&self, inp: &mut Vec<u8>, suffix: Option<Vec<u8>>) -> Vec<u8> {
		// append suffix, pad, ecb encrypt with self.key
		match suffix {
			Some(s) => {
				inp.append(&mut s.clone());
			},
			None => ()
		}
		let mut res = ex9::pkcs7_padding(inp.as_slice(), 16);
		ex10::encrypt_aes128ecb(&mut res, &self.key).expect("couldn't encrypt with ecb");
		res
	}

	pub fn new() -> SingleKeyEncrypter {
		let random_key = ex11::gen_aes128_key();
		SingleKeyEncrypter{key: random_key}
	}
}

pub fn discover_key_size(ske: &SingleKeyEncrypter) -> usize {
	let mut inp_string = "A".to_string();
	let initial_size = ske.encrypt_aes128ecb(&mut inp_string.clone().into_bytes(), Some(suffix())).len();
	loop {
		inp_string.push_str("A");
		let ciphertext = ske.encrypt_aes128ecb(&mut inp_string.clone().into_bytes(), Some(suffix()));
		let current_size = ciphertext.len();
		if current_size != initial_size {
			return current_size - initial_size
		}
	}
}

pub fn make_dictionary(inp: &str, ske: &SingleKeyEncrypter, suffix: &mut Vec<u8>) -> HashMap<u8, Vec<u8>> {
	let inp_bytes = inp.as_bytes().to_vec();
	let mut res = HashMap::new();
	for i in 0..=255 {
		let mut bytes = inp_bytes.clone();
		bytes.push(i);
		res.insert(i, ske.encrypt_aes128ecb(&mut bytes, Some(suffix.to_vec())));
	};
	res
}

pub fn decrypt_suffix() -> String {

	let ske = SingleKeyEncrypter::new();
	let mut my_text = utils::read_file("./src/resources/repeater.txt");
	let encrypted_text = ske.encrypt_aes128ecb(&mut my_text, Some(suffix()));

	let key_size = discover_key_size(&ske);
	println!("key size: {}", key_size);
	println!("using ecb: {}", ex8::detect_aes128ecb(&encrypted_text));

	let one_byte_short = "AAAAAAAAAAAAAAA"; // TODO: make depend on keysize

	let mut res = String::new();

	for i in 0..suffix().len() {
		let mut short_bytes = one_byte_short.as_bytes().to_vec();
		// ::std::ops::RangeFrom{}?
		let test_block = ske.encrypt_aes128ecb(&mut short_bytes, Some(suffix()[i..].to_vec()));
		let dictionary = make_dictionary(one_byte_short, &ske, &mut (suffix()[i..]).to_vec());
		for (j, block) in dictionary {
			if block[..16] == test_block[..16] {
				res.push(char::from(j));
			}
		}
	}
	res
}

pub fn suffix() -> Vec<u8> {
	utils::base64_to_bytes(&"Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK".to_string())
}

/*

|      16       |       16      |       16      |
AAAAAAAAAAAAAAAAhiddentexthiddentexthidden666666

|      16       |       16      |       16      |
AAAAAAAAAAAAAAAhiddentexthiddentexthidden7777777

difference:
one byte short + suffix + padding => encrypted
versus
one byte short + random byte + suffix + padding => encrypted

*/
