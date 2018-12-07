/*

Detect single-character XOR

One of the 60-character strings in this file has been encrypted by single-character XOR.

Find it.

(Your code from #3 should help.)

*/

use crate::set1::ex3::{single_byte_xor, XorResult};
use crate::utils::hex_string_to_bytes;
use std::cmp::Ordering;
use std::fs::File;
use std::io::{BufRead, BufReader};

pub fn detect_xor(input_filename: &str) -> Vec<(usize, XorResult)> {
	let file = File::open(input_filename).expect(&format!("{} not found", input_filename));
	let lines: Vec<Vec<u8>> = BufReader::new(file).lines().map(|line| {
		hex_string_to_bytes(&line.expect("Invalid line"))
	}).collect();
	let mut results: Vec<(usize, XorResult)> = Vec::new();

	for i in 0..lines.len() {
		let best_3 = single_byte_xor(&lines[i], 3);
		for j in best_3 {
			results.push((i,j));
		}
	}
	
	results.sort_by(|x, y| (x.1).partial_cmp(&(y.1)).unwrap_or(Ordering::Less));
	results.reverse();
	results.truncate(5);
	results
}
