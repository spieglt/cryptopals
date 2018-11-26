/*

AES in ECB mode

The Base64-encoded content in this file has been encrypted via AES-128 in ECB mode under the key

"YELLOW SUBMARINE".

(case-sensitive, without the quotes; exactly 16 characters; I like "YELLOW SUBMARINE" because it's exactly 16 bytes long, and now you do too).

Decrypt it. You know the key, after all.

Easiest way: use OpenSSL::Cipher and give it AES-128-ECB as the cipher.
Do this with code.

You can obviously decrypt this using the OpenSSL command-line tool, but we're having you get ECB working in code for a reason. You'll need it a lot later on, and not just for attacking ECB.

*/

use block_modes::{BlockMode, BlockModeError, Ecb};
use block_modes::block_padding::ZeroPadding;
use aes::Aes128;

type Aes128Ecb = Ecb<Aes128, ZeroPadding>;

pub fn decrypt_aes128ecb(inp: &mut Vec<u8>, key: &[u8]) -> Result<(), BlockModeError> {
	let mut cipher = Aes128Ecb::new_varkey(key).expect(&format!("Invalid key length: {}", key.len()));
	cipher.decrypt_nopad(inp)
}
