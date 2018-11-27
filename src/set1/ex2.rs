/*

Fixed XOR

Write a function that takes two equal-length buffers and produces their XOR combination.

If your function works properly, then when you feed it the string:

1c0111001f010100061a024b53535009181c

... after hex decoding, and when XOR'd against:

686974207468652062756c6c277320657965

... should produce:

746865206b696420646f6e277420706c6179

*/

pub fn fixed_xor(a: Vec<u8>, b: Vec<u8>) -> Vec<u8> {
	assert!(a.len() == b.len());

	// let mut result: String = String::new();
	let mut result = vec![];
	for i in 0..a.len() {
		result.push(a[i] ^ b[i]);
	}
	result
}
