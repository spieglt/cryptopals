/*

Single-byte XOR cipher

The hex encoded string:

1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736

... has been XOR'd against a single character. Find the key, decrypt the message.

You can do this by hand. But don't: write code to do it for you.

How? Devise some method for "scoring" a piece of English plaintext. Character frequency is a good metric. Evaluate each output and choose the one with the best score.
Achievement Unlocked

You now have our permission to make "ETAOIN SHRDLU" jokes on Twitter.

*/

use crate::utils::score_characters;
use std::cmp::Ordering;

#[derive(Debug)]
pub struct XorResult {
	pub value: usize,
	pub score: f64,
	pub result_string: Vec<u8>,
}

impl PartialOrd for XorResult {
	fn partial_cmp(&self, other: &XorResult) -> Option<Ordering> {
		if self.score < other.score {
			Some(Ordering::Less)
		} else {
			Some(Ordering::Greater)
		}
	}
}

impl PartialEq for XorResult {
	fn eq(&self, other: &XorResult) -> bool {
		self.score == other.score
	}
}

pub fn single_byte_xor(digits: &Vec<u8>, top_n: usize) -> Vec<XorResult> {
	let mut results: Vec<Vec<u8>> = Vec::new();
	for i in 0..=255 {
		let x = i;
		let mut decoded = vec![];
		for y in digits.iter() {
			decoded.push(x ^ *y);
		}
		results.push(decoded);
	}
	// score and reorder
	let mut scored_results = Vec::new();
	for (i, s) in results.iter().enumerate() {
		// xor value, score, string
		scored_results.push(XorResult{
			value:			i,
			score:			score_characters(s),
			result_string:	s.to_vec()
		});
	}
	scored_results.sort_by(|x, y| { x.partial_cmp(y).unwrap_or(Ordering::Less) });
	scored_results.reverse();
	scored_results.truncate(top_n);
	scored_results
}

