/*

Implement CBC mode

CBC mode is a block cipher mode that allows us to encrypt irregularly-sized messages, despite the fact that a block cipher natively only transforms individual blocks.

In CBC mode, each ciphertext block is added to the next plaintext block before the next call to the cipher core.

The first plaintext block, which has no associated previous ciphertext block, is added to a "fake 0th ciphertext block" called the initialization vector, or IV.

Implement CBC mode by hand by taking the ECB function you wrote earlier, making it encrypt instead of decrypt (verify this by decrypting whatever you encrypt to test), and using your XOR function from the previous exercise to combine them.

The file here is intelligible (somewhat) when CBC decrypted against "YELLOW SUBMARINE" with an IV of all ASCII 0 (\x00\x00\x00 &c)

*/

use ex2;

use aes::block_cipher_trait::generic_array::GenericArray;
use block_modes::{BlockMode, BlockModeError, BlockModeIv, Cbc, Ecb};
use block_modes::block_padding::ZeroPadding;
use aes::Aes128;

type Aes128Cbc = Cbc<Aes128, ZeroPadding>;
type Aes128Ecb = Ecb<Aes128, ZeroPadding>;

// encrypts in place
pub fn encrypt_aes128ecb(inp: &mut Vec<u8>, key: &[u8]) -> Result<(), BlockModeError> {
	let mut cipher = Aes128Ecb::new_varkey(key).expect("problem creating key");
	cipher.encrypt_nopad(inp)
}
// decrypts in place
pub fn decrypt_aes128cbc(inp: &mut Vec<u8>, key: &[u8], iv: &[u8]) -> Result<(), BlockModeError> {
	let mut cipher = Aes128Cbc::new_varkey(key, GenericArray::from_slice(iv)).expect("problem creating aes cbc cipher");
	cipher.decrypt_nopad(inp)
}

// does not modify input
pub fn encrypt_aes128cbc(inp: &Vec<u8>, key: &[u8], iv: &[u8]) -> Vec<u8> {
	assert!(inp.len() % key.len() == 0);
	let key_len = key.len();
	let num_chunks = inp.len() / key.len();
	let mut res: Vec<u8> = Vec::new();
	for i in 0..num_chunks {
		let current_block = inp[i*key_len..(i+1)*key_len].to_vec();
		let previous_block = match i == 0 {
			true => iv.to_vec(),
			false => {
				let mut temp = vec![0; key.len()];
				temp.copy_from_slice(&res[(i-1)*key_len..i*key_len]);
				temp
			}
		};
		let mut xor_block = ex2::fixed_xor(current_block.to_vec(), previous_block);
		encrypt_aes128ecb(&mut xor_block, key).expect("could not encrypt");
		res.append(&mut xor_block);
	}
	assert!(res.len() == inp.len());
	res
}

#[cfg(test)]
mod tests {
	use ex7;
	use ex10;

	#[test]
	fn test_ecb_encryption_and_decryption() {
		// raw_mangoes.len() == 160, a multiple of blocksize
		let raw_mangoes = "MANGO SALSA YES MANGO SALSA YES MANGO SALSA YES \
			MANGO SALSA YES MANGO SALSA YES MANGO SALSA YES MANGO SALSA YES \
			MANGO SALSA YES MANGO SALSA YES MANGO SALSA YES ".as_bytes().to_vec();
		let mut encrypted_mangoes = raw_mangoes.clone();
		ex10::encrypt_aes128ecb(&mut encrypted_mangoes, "sixteencharacter".as_bytes()).expect("could not encrypt");
		ex7::decrypt_aes128ecb(&mut encrypted_mangoes, "sixteencharacter".as_bytes()).expect("could not decrypt");
		assert!(raw_mangoes == encrypted_mangoes);
	}
}

