/*

ECB cut-and-paste

Write a k=v parsing routine, as if for a structured cookie. The routine should take:

foo=bar&baz=qux&zap=zazzle

... and produce:

{
  foo: 'bar',
  baz: 'qux',
  zap: 'zazzle'
}

(you know, the object; I don't care if you convert it to JSON).

Now write a function that encodes a user profile in that format, given an email address. You should have something like:

profile_for("foo@bar.com")

... and it should produce:

{
  email: 'foo@bar.com',
  uid: 10,
  role: 'user'
}

... encoded as:

email=foo@bar.com&uid=10&role=user

Your "profile_for" function should not allow encoding metacharacters (& and =). Eat them, quote them, whatever you want to do, but don't let people set their email address to "foo@bar.com&role=admin".

Now, two more easy functions. Generate a random AES key, then:

    Encrypt the encoded user profile under the key; "provide" that to the "attacker".
    Decrypt the encoded user profile and parse it.

Using only the user input to profile_for() (as an oracle to generate "valid" ciphertexts) and the ciphertexts themselves, make a role=admin profile.

*/

use crate::set2::ex12;
use crate::utils;
use aes::Aes128;
use block_modes::{BlockMode, BlockModeError, Ecb};
use block_modes::block_padding::Pkcs7;
use std::collections::HashMap;

type Aes128EcbPkcs7 = Ecb<Aes128, Pkcs7>;

impl ex12::SingleKeyEncrypter {

	pub fn decrypt_aes128ecb<'a>(&self, inp: &'a mut Vec<u8>) -> Result<&'a[u8], BlockModeError> {
		let cipher = Aes128EcbPkcs7::new_varkey(&self.key).expect("problem creating key");
		cipher.decrypt_pad(inp)
	}

	pub fn make_forged_block(&self) -> Vec<u8> {
		// find block size. make "email=" + chars = blocksize, then add "admin00000000..."
		let block_size = ex12::discover_key_size(&self);
		let leading_char_num = block_size - ("email=".len() % block_size);

		let mut offset_plus_forged_block: Vec<u8> = vec![];
		offset_plus_forged_block.append(&mut "0".repeat(leading_char_num).into_bytes());
		offset_plus_forged_block.append(&mut "admin".as_bytes().to_vec());
		let pad_num = (block_size - "admin".len()) as u8;
		let mut padding: Vec<u8> = Vec::new();
		for _i in 0..pad_num {
			padding.push(pad_num);
		};
		offset_plus_forged_block.append(&mut padding);
	
		let mut bytes_with_forgery = profile_for(&mut offset_plus_forged_block);
		println!("bytes_with_forgery:");
		utils::print_invalid_string(&bytes_with_forgery);
		let encrypted_with_forgery = self.encrypt_aes128ecb(&mut bytes_with_forgery, None);
		// will be email.len() / block size + 1
		let fb_index = ("email=".len() / block_size) + 1;
		encrypted_with_forgery[(fb_index * block_size)..((fb_index + 1) * block_size)].to_vec()
	}

	pub fn align_role_block(&self) -> Vec<u8> {
		// find amount of padding. start with 1 char, increment till block is added?
		// not necessary. just make "email=" + chars + "&uid=10&role=" % block size == 0.
		let block_size = ex12::discover_key_size(&self);
		let num_chars = block_size - ( ("email=".len() + "&uid=10&role=".len()) % block_size );
		let mut inp = profile_for(&mut "A".repeat(num_chars).into_bytes());
		self.encrypt_aes128ecb(&mut inp, None)
	}
}

pub fn kv_parse(inp: &str) -> HashMap<String, String> {
	// split string along &
	// for each substring, split along =
	// make left side key, right side value. append to result.
	let mut res = HashMap::new();

	for s in inp.split('&') {
		let mut pair = s.split('=');
		match (pair.next(), pair.next()) {
			(Some(k), Some(v)) => {
				res.insert(k.to_string(), v.to_string());
			},
			_ => println!("invalid input")
		}
	}
	res
}

pub fn profile_for(inp: &mut Vec<u8>) -> Vec<u8> {
	// clean input
	inp.retain(|c| !(c == &b'&' || c == &b'='));
	
	let mut res: Vec<u8> = Vec::new();
	let x = [
		("email".to_string().into_bytes(), inp.clone()),
		("uid".to_string().into_bytes(), "10".to_string().into_bytes()),
		("role".to_string().into_bytes(), "user".to_string().into_bytes())
	];
	// let mut map = HashMap::new();
	// for (i, j) in x.iter() {
	// 	map.insert(i, j);
	// }

	for (i, (key, val)) in x.iter().enumerate() {
		if i != 0 {
			res.push(b'&');
		}
		let (mut k, mut v) = ((*key).clone(), (*val).clone());
		res.append(&mut k);
		res.push(b'=');
		res.append(&mut v);
	}
	res
}

pub fn ecb_cut_and_paste() -> HashMap<String, String> {
	let kc = ex12::SingleKeyEncrypter::new();
	let block_size = ex12::discover_key_size(&kc);
	// step one: get forged block
	let forged_block = kc.make_forged_block();
	println!("forged_block: {:02x?}", forged_block);
	// step two: get encrypted bytes with aligned role
	let mut aligned_role_block = kc.align_role_block();
	println!("pre-slice : {:02x?}", aligned_role_block);
	// step three: swap out last block of aligned block with forged block
		// get last block: len - blocksize .. len
	let last_block_start = aligned_role_block.len() - block_size;
	let block_len = aligned_role_block.len();
	aligned_role_block.splice(last_block_start..block_len, forged_block);
	println!("post-slice: {:02x?}", aligned_role_block);
	// step four: decrypt swapped bytes
	let mut decrypted_bytes: Vec<u8> = vec![];
	match kc.decrypt_aes128ecb(&mut aligned_role_block) {
		Ok(x) => {decrypted_bytes = x.to_vec();},
		Err(x) => {println!("decrypt error: {:?}", x);}
	}
	// step five: parse swapped bytes and return as Hashmap
	let cookie_string = String::from_utf8_lossy(&decrypted_bytes).clone();
	kv_parse(&cookie_string)
}

/*

                |                |                |                |
email=0&uid=10&r|ole=user88888888|                |                |
email=00&uid=10&|role=user7777777|                |                |
                |                |                |                |
email=0000000000|000&uid=10&role=|userTTTTTTTTTTTT|                |
email=0000000000|000&uid=10&role=|adminEEEEEEEEEEE|                |
                |                |                |                |
                |[special block] |                |                |
email=0000000000|admin00000000000|&uid=10&role=use|r000000000000000|
                |                |                |                |
                |                |                |                |
email=0000000000|000&uid=10&role=|userTTTTTTTTTTTT|                | aligned last block, to swap out with special block
                |                |                |                |
                |                |                |                |


*/
