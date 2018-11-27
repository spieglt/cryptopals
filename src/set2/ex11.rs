/*

Now that you have ECB and CBC working:

Write a function to generate a random AES key; that's just 16 random bytes.

Write a function that encrypts data under an unknown key --- that is, a function that generates a random key and encrypts under it.

The function should look like:

encryption_oracle(your-input)
=> [MEANINGLESS JIBBER JABBER]

Under the hood, have the function append 5-10 bytes (count chosen randomly) before the plaintext and 5-10 bytes after the plaintext.

Now, have the function choose to encrypt under ECB 1/2 the time, and under CBC the other half (just use random IVs each time for CBC). Use rand(2) to decide which to use.

Detect the block cipher mode the function is using each time. You should end up with a piece of code that, pointed at a block box that might be encrypting ECB or CBC, tells you which one is happening.

*/

use ex9;
use ex10;
use rand::{thread_rng, Rng};

pub fn gen_aes128_key() -> [u8;16] {
	let mut x = [0u8; 16];
	let mut g = thread_rng();
	g.fill(&mut x);
	x
}

pub fn encrypt_randomly(inp: &[u8]) -> Vec<u8> {
	let mut g = thread_rng();
	let mut bytes_before = [0u8; 10];
	let mut bytes_after = [0u8; 10];
	g.fill(&mut bytes_before);
	g.fill(&mut bytes_after);

	// before append inp append after
	let mut inp_vec = inp.to_vec();
	inp_vec.append(&mut bytes_after[0..g.gen_range(5,10)].to_vec());
	let mut all_bytes = bytes_before[0..g.gen_range(5,10)].to_vec();
	all_bytes.append(&mut inp_vec);
	println!("all_bytes len: {}", all_bytes.len());
	let mut padded_bytes = ex9::pkcs7_padding(all_bytes.as_slice(), 16);
	let key = gen_aes128_key();
	if g.gen() {
		println!("using: ECB");
		ex10::encrypt_aes128ecb(&mut padded_bytes, &key).expect("couldn't encrypt with ecb");
		padded_bytes
	} else {
		println!("using: CBC");
		let iv = gen_aes128_key();
		ex10::encrypt_aes128cbc(&padded_bytes, &key, &iv)
	}
}
