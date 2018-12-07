/*

Byte-at-a-time ECB decryption (Harder)

Take your oracle function from #12. Now generate a random count of random bytes and prepend this string to every plaintext. You are now doing:

AES-128-ECB(random-prefix || attacker-controlled || target-bytes, random-key)

Same goal: decrypt the target-bytes.
Stop and think for a second.

What's harder than challenge #12 about doing this? How would you overcome that obstacle? The hint is: you're using all the tools you already have; no crazy math is required.

Think "STIMULUS" and "RESPONSE".

*/

// new struct? or function that appends prefix before encrypting?
// that would be inconvenient, would have to pass the keychain into the function
// what we need to do is just switch suffix to prefix? what is specific to keychain about suffix?
// nothing, they're unrelated. so encrypt_aes128ecb could be encrypt_aes128ecb_with_suffix, and a
// prefix function. but why not just make one Option flag for prefix, one for suffix, and keep the rest the same?
// that's the answer.
// or make a struct with an enum to match on type. no, because we need prefix AND unknown suffix.
// need nesting type.

use crate::set2::ex12;
use std::collections::HashMap;
use rand::{thread_rng, Rng};

pub struct SKEWithPrefix {
	prefix: Vec<u8>,
	ske: ex12::SingleKeyEncrypter,
}

impl SKEWithPrefix {
	pub fn new() -> Self {
		let mut g = thread_rng();
		let prefix_len: usize = g.gen_range(0, 40);
		println!("prefix len: {}", prefix_len);
		let prefix: Vec<u8> = (0..prefix_len).map(|_| {
			g.gen()
		}).collect();
		println!("prefix: {:02x?}", prefix);
		SKEWithPrefix{
			prefix: prefix.to_vec(),
			ske: ex12::SingleKeyEncrypter::new(),
		}
	}

	// wrapper for ske's encrypt method
	pub fn encrypt_aes128ecb(&self, inp: &mut Vec<u8>, suffix: Option<Vec<u8>>) -> Vec<u8> {
		// wrap input and prefix together
		let mut input_with_prefix = (&self.prefix).clone();
		input_with_prefix.append(inp);
		let encrypted = &self.ske.encrypt_aes128ecb(&mut input_with_prefix, suffix);
		encrypted.to_vec()
	}
}


fn find_padding(skewp: &SKEWithPrefix) -> usize {
	let init_len = skewp.encrypt_aes128ecb(&mut vec![], Some(ex12::suffix())).len();
	for i in 0..40 {
		if init_len != skewp.encrypt_aes128ecb(&mut vec!['A' as u8; i], Some(ex12::suffix())).len() {
			return i;
		}
	}
	0
}

pub fn make_dictionary(inp: &Vec<u8>, skewp: &SKEWithPrefix, suffix: &mut Vec<u8>) -> HashMap<u8, Vec<u8>> {
	let mut res = HashMap::new();
	for i in 0..=255 {
		// input here needs to be prefix plus filler... does it? can we just let skewp's method apply prefix? yes.
		// input just needs to be filler
		let mut bytes = inp.clone();
		bytes.push(i);
		res.insert(i, skewp.encrypt_aes128ecb(&mut bytes, Some(suffix.to_vec())));
	};
	res
}

pub fn decrypt_suffix_with_random_prefix() -> String {
	let skewp = SKEWithPrefix::new();
	let block_size = ex12::discover_key_size(&skewp.ske);
	let encrypted_len = skewp.encrypt_aes128ecb(&mut vec![], Some(ex12::suffix())).len();

	let padding_len = find_padding(&skewp);
	println!("padding_len: {}", padding_len);

	let prefix_len = encrypted_len - padding_len - ex12::suffix().len();
	let byte_trap_filler_len = block_size - 1 - (prefix_len % block_size);

	let mut res = String::new();

	for i in 0..ex12::suffix().len() {
		let ciphertext_with_trap = skewp.encrypt_aes128ecb(&mut vec!['A' as u8; byte_trap_filler_len], Some(ex12::suffix()[i..].to_vec()));
		let trap_block_number = prefix_len / block_size;
		let trap_blocks = ciphertext_with_trap[..(trap_block_number + 1) * block_size].to_vec();

		let dictionary = make_dictionary(&mut vec!['A' as u8; byte_trap_filler_len], &skewp, &mut (ex12::suffix()[i..]).to_vec());
		for (j, blocks) in dictionary {
			if blocks[..(trap_block_number + 1) * block_size] == trap_blocks[..(trap_block_number + 1) * block_size] {
				res.push(char::from(j));
			}
		}
	}
	res
}

// will adding one byte change anything? no, because it's padded either way.

/*
				|                |                |                |
				|                |                |                |
randomprefixAAAA|AAAAAAAAAAAAsecr|ettextishere4444|                |
				|                |                |                |
				|                |                |                |
randomprefixsecr|ettextishere4444|                |                |
randomprefixAsec|rettextishere333|                |                |
randomprefixAAse|crettextishere22|                |                |
randomprefixAAAs|ecrettextishere1|                |                |
randomprefixAAAA|secrettextishere|SSSSSSSSSSSSSSSS|                |  S == 16
				|                |                |                |
				|                |                |                |
				|                |                |                |
				|                |                |                |
				|                |                |                |
verylongrandompr|efixsecrettextis|hereTTTTTTTTTTTT|                | T = 12
verylongrandompr|efixAAAAAAAAAAAA|secrettextishere|SSSSSSSSSSSSSSSS| 12 A's
                |                |                |                |
                |                |                |                |
                |                |                |                |
                |                |                |                |


1. find pad length
2. find prefix length
3. make byte trap
4. compare trapped block to dictionary

Start with no filler characters. Len = prefix + secrettext + padding. How much is padding?
Took four filler chars to make a new block.
That means original padding must have been 4.
That means prefix length = encrypted length - padding - secret text.

Need prefix + filler % blocksize to equal blocksize - 1
prefix % blocksize + filler = 15
prefix % blocksize - 15 = -filler
filler = 15 - prefix % blocksize

// Then make randomprefix + filler chars + secret text = encryption, then grab appropriate block of this, floor_div(len(prefix), blocksize).
// Compare that to a dictionary of (prefix + (padding number of filler chars - 1) + byte from 0..256)
// That will now be the first byte of secret text. Repeat for len of secret text, add to result.

	??? verylongrandomprefix = len 20
	??? 20 % blocksize = 4
	??? Need blocksize - 4 - 1 filler chars to make a single last char comparison trap.

*/