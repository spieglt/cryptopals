/*

Break repeating-key XOR
It is officially on, now.

This challenge isn't conceptually hard, but it involves actual error-prone coding. The other challenges in this set are there to bring you up to speed. This one is there to qualify you. If you can do this one, you're probably just fine up to Set 6.

There's a file here. It's been base64'd after being encrypted with repeating-key XOR.

Decrypt it.

Here's how:

    Let KEYSIZE be the guessed length of the key; try values from 2 to (say) 40.
    Write a function to compute the edit distance/Hamming distance between two strings. The Hamming distance is just the number of differing bits. The distance between:

    this is a test

    and

    wokka wokka!!!

    is 37. Make sure your code agrees before you proceed.
    For each KEYSIZE, take the first KEYSIZE worth of bytes, and the second KEYSIZE worth of bytes, and find the edit distance between them. Normalize this result by dividing by KEYSIZE.
    The KEYSIZE with the smallest normalized edit distance is probably the key. You could proceed perhaps with the smallest 2-3 KEYSIZE values. Or take 4 KEYSIZE blocks instead of 2 and average the distances.
    Now that you probably know the KEYSIZE: break the ciphertext into blocks of KEYSIZE length.
    Now transpose the blocks: make a block that is the first byte of every block, and a block that is the second byte of every block, and so on.
    Solve each block as if it was single-character XOR. You already have code to do this.
    For each block, the single-byte XOR key that produces the best looking histogram is the repeating-key XOR key byte for that block. Put them together and you have the key.

This code is going to turn out to be surprisingly useful later on. Breaking repeating-key XOR ("Vigenere") statistically is obviously an academic exercise, a "Crypto 101" thing. But more people "know how" to break it than can actually break it, and a similar technique breaks something much more important.
No, that's not a mistake.

We get more tech support questions for this challenge than any of the other ones. We promise, there aren't any blatant errors in this text. In particular: the "wokka wokka!!!" edit distance really is 37.

*/


use crate::utils::*;
use crate::set1::ex3;
use crate::set1::ex5;
use std::cmp::Ordering::Less;
use std::fs;

pub fn hamming_distance(a: &[u8], b: &[u8]) -> usize {
	assert!(a.len() == b.len());
	let mut score = 0;
	for i in 0..a.len() {
		for j in 0..8 {
			if nth_bit_set(a[i], j) ^ nth_bit_set(b[i], j) {
				score += 1;
			}
		}
	}
	score
}

fn nth_bit_set(num: u8, nth: u8) -> bool {
	num & 2u8.pow(nth as u32) == 2u8.pow(nth as u32)
}

fn find_best_key_sizes(file: &Vec<u8>, top_n: usize) -> Vec<(f64, usize)> {
	let mut results: Vec<(f64, usize)> = Vec::new();

	for i in 2..41 {
		// get num chunks = file / i
		// for num chunks, get ham_dist and add to total
		// div total by num chunks and by keysize and append to results
		let mut total = 0.0;
		let num_whole_chunks = file.len() / i;
		let num_chunk_pairs = num_whole_chunks / 2;
		for j in 0..num_chunk_pairs {

			// if len = 93 and i = 8, then num_chunk_pairs = 5,
			// and we want to grab first 8 and compare to next 8,
			// then grab 3rd 8 and compare to 4th 8, etc.
			// won't go over because we floor div'd and only going up to 5.

			let ham_dist = hamming_distance(
				&file[j*i..(j+1)*i],
				&file[(j+1)*i..(j+2)*i]
			) as f64;
			total += ham_dist as f64 / i as f64;
		}
		let avg_dist = total / num_chunk_pairs as f64;
		results.push((avg_dist, i));
	}
	results.sort_by(|x, y| x.partial_cmp(y).unwrap_or(Less));
	results.truncate(top_n);
	results
}

pub fn break_repeating_key_xor_full(input: &str) {

    let inp_string = fs::read_to_string(input)
    	.expect(&format!("unable to read file {}", input));
	let bytes = base64_to_bytes(&inp_string);

	let sizes = find_best_key_sizes(&bytes, 4);
	println!("sizes: {:?}", sizes);
	let key_size = sizes[0].1;

	let (key, decrypted) = break_repeating_key_xor(&bytes, key_size);
	println!("key: {:02x?}", key);
	println!("decrypted:");
	print_invalid_string(&decrypted);
}

pub fn break_repeating_key_xor(ciphertext: &Vec<u8>, key_size: usize) -> (Vec<u8>, Vec<u8>) {
	
	let block: Vec<u8> = Vec::new();
	let num_blocks = ceil(ciphertext.len(), key_size);
	let mut blocks: Vec<Vec<u8>> = Vec::new();

	// split into blocks of key_size
	for i in 0..num_blocks {
		if i < num_blocks - 1 {
			blocks.push(ciphertext[i*key_size..(i+1)*key_size].to_vec());
		} else if i == num_blocks - 1 {
			blocks.push(ciphertext[i*key_size..].to_vec());
		}
	}

	// make key_size number of blocks and fill with contents of previous blocks
	let mut transposed_blocks = vec![block; key_size];
	for bl in blocks.iter() {
		for (i,by) in bl.iter().enumerate() {
			transposed_blocks[i].push(*by);
		}
	}

	let mut key: Vec<u8> = Vec::new();
	for bl in transposed_blocks {
		// grab value with best single_byte_xor score
		let res = &ex3::single_byte_xor(&bl.to_vec(), 1)[0];
		key.push(res.value as u8);
	}
	(key.clone(), ex5::repeating_key_xor(ciphertext, &key))
}
