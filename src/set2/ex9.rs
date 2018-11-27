/*

Implement PKCS#7 padding

A block cipher transforms a fixed-sized block (usually 8 or 16 bytes) of plaintext into ciphertext. But we almost never want to transform a single block; we encrypt irregularly-sized messages.

One way we account for irregularly-sized messages is by padding, creating a plaintext that is an even multiple of the blocksize. The most popular padding scheme is called PKCS#7.

So: pad any block to a specific block length, by appending the number of bytes of padding to the end of the block. For instance,

"YELLOW SUBMARINE"

... padded to 20 bytes would be:

"YELLOW SUBMARINE\x04\x04\x04\x04"

*/

pub fn pkcs7_padding(inp: &[u8], block_size: usize) -> Vec<u8> {
	let mut res = inp.to_vec();
	let diff = block_size - (res.len() % block_size);
	// first push before while loop needed to ensure that padding block is tacked on even if
	// input length is a multiple of block size.
	res.push(diff as u8);
	while res.len() % block_size != 0 {
		res.push(diff as u8);
	}
	res
}
