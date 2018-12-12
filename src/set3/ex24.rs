/*

Create the MT19937 stream cipher and break it

You can create a trivial stream cipher out of any PRNG; use it to generate a sequence of 8 bit outputs and call those outputs a keystream. XOR each byte of plaintext with each successive byte of keystream.

Write the function that does this for MT19937 using a 16-bit seed. Verify that you can encrypt and decrypt properly. This code should look similar to your CTR code.

Use your function to encrypt a known plaintext (say, 14 consecutive 'A' characters) prefixed by a random number of random characters.

From the ciphertext, recover the "key" (the 16 bit seed).

Use the same idea to generate a random "password reset token" using MT19937 seeded from the current time.

Write a function to check if any given password token is actually the product of an MT19937 PRNG seeded with the current time.

*/

use crate::set3::ex21;

pub fn encrypt_mt19937_stream_cipher(inp: &mut Vec<u8>, seed: u16) {
	let mut twister = ex21::MtPrng::new();
	twister.seed_mt(seed.into());
	let mut next_four = [0u8; 4];
	for i in 0..inp.len() {
		if i % 4 == 0 {
			unsafe { 
				next_four = std::mem::transmute(
					twister.extract_number()
						.expect("could not extract number")
						.to_be()
				);
			}
		}
		inp[i] ^= next_four[i%4];
	}
}

pub fn mt19937_stream_cipher() {

}

mod tests {
	use rand::{Rng, thread_rng};
	#[test]
	fn verify_that_you_can_encrypt_and_decrypt_properly() {
		let mut sample_data: Vec<u8> = "Create the MT19937 stream cipher and break it\n\
			You can create a trivial stream cipher out of any PRNG; use it to generate a sequence of 8 bit outputs and call those outputs a keystream. XOR each byte of plaintext with each successive byte of keystream.\n\
			Write the function that does this for MT19937 using a 16-bit seed. Verify that you can encrypt and decrypt properly. This code should look similar to your CTR code.\n\
			Use your function to encrypt a known plaintext (say, 14 consecutive 'A' characters) prefixed by a random number of random characters.\n\
			From the ciphertext, recover the \"key\" (the 16 bit seed).\n\
			Use the same idea to generate a random \"password reset token\" using MT19937 seeded from the current time.\n\
			Write a function to check if any given password token is actually the product of an MT19937 PRNG seeded with the current time."
			.bytes().collect();
		let clone_data = sample_data.clone();
		let num: u16 = rand::thread_rng().gen();
		super::encrypt_mt19937_stream_cipher(&mut sample_data, num);
		println!("{}", String::from_utf8_lossy(&sample_data));
		super::encrypt_mt19937_stream_cipher(&mut sample_data, num);
		println!("{}", String::from_utf8_lossy(&sample_data));
		assert_eq!(sample_data, clone_data);
	}
}
