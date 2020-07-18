use std::fs::File;
use std::io::{BufRead, BufReader, Read};

pub fn hex_string_to_bytes(inp: &str) -> Vec<u8> {

	assert!(inp.len() % 2 == 0);
	let mut bytes: Vec<u8> = Vec::new();

	for x in 0..inp.len() {
		if x % 2 == 0 {
			let byte_str = &inp[x..x+2];
			bytes.push(u8::from_str_radix(byte_str, 16).expect("invalid byte"));
		}
	}

	bytes
}

pub fn base64_to_bytes(inp: &String) -> Vec<u8> {
	let symbols = "ABCDEFGHIJKLMNOPQRSTUVWXYZ\
		abcdefghijklmnopqrstuvwxyz\
		0123456789+/".to_string();
	let chs = inp.chars();
	let mut bytes: Vec<u8> = Vec::new();

	let mut i = 0;
	for c in chs {
		let idx = symbols.find(c);
		match idx {
			Some(x_usize) => {
				let x = x_usize as u8;
				if i % 4 == 0 {
					// just take all 6 bits of current byte and left-shift by 2
					bytes.push(x << 2);
				} else if i % 4 == 1 {
					// add bottom 4 bits of current idx to new byte, left-shifted by 4
					bytes.push((x & ((1 << 4) - 1)) << 4);
					// then add top 2 bits of current idx to previous byte
					let new_byte = bytes.len() - 1;
					bytes[new_byte - 1] += x >> 4;
				} else if i % 4 == 2 {
					// grab bottom two bits and add to new byte, left-shifted by 6
					bytes.push((x & ((1 << 2) - 1)) << 6);
					// then grab top 4 bits, add to previous
					let new_byte = bytes.len() - 1;
					bytes[new_byte - 1] += x >> 2;
				} else if i % 4 == 3 {
					// just add entire 6-bit value to last byte
					let new_byte = bytes.len() - 1;
					bytes[new_byte] += x;
				}
				// only keep track of base64 chars, ignore newlines
				i += 1;
			},
			None => (),
		}
		if c == '=' {
			// chop one byte and break
			let l = bytes.len();
			bytes.truncate(l - 1);
			break;
		}
	}
	bytes
}

pub fn score_characters(chars: &Vec<u8>) -> f64 {
	let mut score = 0.0;
	let letter_frequencies = vec![
		8.167, 1.492, 2.782, 4.253, 12.702, 2.228, 2.015,
		6.094, 6.966, 0.153, 0.772, 4.025, 2.406, 6.749,
		7.507, 1.929, 0.095, 5.987, 6.327, 9.056, 2.758,
		0.978, 2.360, 0.150, 1.974, 0.074,
	];
	for c in chars.iter() {
		match c {
			0x20 => score += 5.0,	// give points for spaces why not
			0x41 ..= 0x5a => {		// uppercase
				score += letter_frequencies[(c - 0x41) as usize];
			},
			0x61 ..= 0x7a => {		// lowercase
				score += letter_frequencies[(c - 0x61) as usize];
			},
			0x21 ..= 0x7e => (),	// printable
			_ => {					// if not printable, penalize
				score -= 10.0;
			}
		}
	}
	score
}

pub fn read_file(name: &str) -> Vec<u8> {
	let mut res = vec![];
	let mut file = File::open(name).expect(&format!("file {} not found", name));
	file.read_to_end(&mut res).expect(&format!("could not read file {}", name));
	res
}

pub fn b64_file_to_byte_lines(filename: &str) -> Vec<Vec<u8>> {
	let file = File::open(filename).expect(&format!("file {} not found", filename));
	BufReader::new(file).lines().map(|line| {
		base64_to_bytes(&line.expect("invalid line"))
	}).collect()
}

pub fn hex_file_to_byte_lines(filename: &str) -> Vec<Vec<u8>> {
	let file = File::open(filename).expect(&format!("file {} not found", filename));
	BufReader::new(file).lines().map(|line| {
		hex_string_to_bytes(&line.expect("invalid line"))
	}).collect()
}

pub fn print_invalid_string(inp: &[u8]) {
	for c in inp.iter() {
		if (*c as char).is_ascii_alphanumeric() || (*c as char).is_ascii_punctuation() || (*c as char).is_ascii_whitespace() {
			print!("{}", *c as char);
		} else {
			print!("\\x{:02x}", c);
		}
	}
	println!();
}

pub fn ceil(num: usize, denom: usize) -> usize {
	if num % denom != 0 {
		return num / denom + 1;
	}
	num / denom
}

pub fn min(x: usize, y: usize) -> usize {
	match x < y {
		true => x,
		false => y,
	}
}
