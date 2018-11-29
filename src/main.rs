mod utils;

// set 1
mod set1;
use set1::*;

// set 2
mod set2;
use set2::*;

// set 3
mod set3;
use set3::*;

extern crate aes;
extern crate block_modes;
extern crate rand;

use std::iter::FromIterator;

fn main() {
	for a in std::env::args() {
		match a.as_str() {
			"all" => { set_one(); set_two(); set_three(); return; },
			"1" => { set_one(); return; },
			"2" => { set_two(); return; },
			"3" => { set_three(); return; },
			_ => (),
		}
	}
	current_exercise();
}

fn set_one() {

	// ex1
	println!("\nex1:");
	let hex = utils::hex_string_to_bytes("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d");
	println!("{}", String::from_iter(&ex1::bytes_to_base64(hex)));
	// other way:
	// let x: String = std::iter::FromIterator::from_iter(ex1::bytes_to_base64(hex));
	// println!("{}", x);

	// ex2
	println!("\nex2:");
	let a = utils::hex_string_to_bytes("1c0111001f010100061a024b53535009181c");
	let b = utils::hex_string_to_bytes("686974207468652062756c6c277320657965");
	println!("{:02x?}", &ex2::fixed_xor(a, b));

	// ex3
	println!("\nex3:");
	let secret = utils::hex_string_to_bytes("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736");
	for line in ex3::single_byte_xor(&secret, 5).iter() {
		println!(
			"i = {}: {}",
			line.value,
			String::from_utf8_lossy(&line.result_string)
		);
	}

	// ex4
	println!("\nex4:");
	let ex4_results = ex4::detect_xor("./src/resources/4.txt");
	for line in ex4_results.iter() {
		println!("line {} ({:.2}): {}",
			line.0, (line.1).score,
			String::from_utf8_lossy(&(line.1).result_string)
		);
	}

	// ex5
	let key_5 = "ICE".bytes().collect();
	// instead of "ICE".to_string().into_bytes()
	let input_5 = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal".bytes().collect();
	println!("\nex5: {:02x?}", ex5::repeating_key_xor(&input_5, &key_5));

	// ex6
	let a: Vec<u8> = "this is a test".bytes().collect();
	let b: Vec<u8> = "wokka wokka!!!".bytes().collect();
	// type annotations necessary because hamming_distance takes &[u8]
	// if annotation omitted, a's type is inferred to be &[u8], which doesn't satisfy bytes().collect()
	println!("\nex6:\nhamming_distance: {}", ex6::hamming_distance(&a, &b));
	ex6::break_repeating_key_xor_full("./src/resources/6.txt");

	// ex7
	let encoded7 = utils::read_file("./src/resources/7.txt");
	let mut encrypted7 = utils::base64_to_bytes(&String::from_utf8_lossy(&encoded7).to_string());
	ex7::decrypt_aes128ecb(&mut encrypted7, "YELLOW SUBMARINE".as_bytes()).expect("could not decrypt");
	println!("\n\nex7:\n{}", String::from_utf8_lossy(&encrypted7));

	// ex8
	println!("\nex8:");
	let inp = utils::hex_file_to_byte_lines("./src/resources/8.txt");
	for i in 0..inp.len() {
		if ex8::detect_aes128ecb(&inp[i]) {
			println!("index of ecb-encrypted string: {}\nline: {:02x?}", i, inp[i]);
		}
	}

}

fn set_two() {

	// ex9
	println!("\nex9:");
	utils::print_invalid_string(&ex9::pkcs7_padding("TACOS AL CARBON SI VOUS PLAIT".as_bytes(), 16));
	utils::print_invalid_string(&ex9::pkcs7_padding("SIXTEENCHARACTER".as_bytes(), 16));

	// ex10
	let encoded = utils::read_file("./src/resources/10.txt");
	let mut ciphertext_ex10 = utils::base64_to_bytes(&String::from_utf8_lossy(&encoded).to_string());
	let encrypted_clone = ciphertext_ex10.clone();
	let iv0 = [0; 16];
	ex10::decrypt_aes128cbc(&mut ciphertext_ex10, "YELLOW SUBMARINE".as_bytes(), &iv0)	// doesn't unpad
		.expect("couldn't decrypt with cbc");
	println!("\nex10:\n{}", String::from_utf8_lossy(&ciphertext_ex10));

	let reencrypted = ex10::encrypt_aes128cbc(&ciphertext_ex10, "YELLOW SUBMARINE".as_bytes(), &iv0);
	assert!(reencrypted[0..32] == encrypted_clone[0..32]);
	// last blocks won't be the same as the decryption didn't unpad, but enough to check the first two blocks

	// ex11
	println!("\nex11:\nrandom key: {:x?}", ex11::gen_aes128_key());
	let files = [
		// "./src/resources/sample.txt",
		// "./src/resources/2000px-Tux.svg.png",
		// "./src/resources/indonesia_sulawesi_171067.jpg",
		"./src/resources/repeater.txt"
	];
	for f in files.iter() {
		println!("file: {}", f);
		for _ in 0..4 {
			let mut file = utils::read_file(f);
			let encrypted = ex11::encrypt_randomly(&file);
			let d = if ex8::detect_aes128ecb(&encrypted) { "ECB" } else { "CBC" };
			println!("detected: {}", d);
		}
		println!();
	}

	// ex12
	println!("\nex12:\n{}", ex12::decrypt_suffix());

	// ex13
	println!("\nex13:");
	let map = ex13::kv_parse("foo=bar&baz=qux&zap=zazzle");
	println!("MAP: {:?}", map);
	// println!("string: {:02x?}", ex13::profile_for(&mut "foobar@ham&sand=wich.org".as_bytes().to_vec()));
	println!("ECB cut and paste: {:?}", ex13::ecb_cut_and_paste());

	// ex14
	println!("\nex14:\n{}", ex14::decrypt_suffix_with_random_prefix());

	// ex15
	println!("\nex15:");
	let mut input = "THIRTEENCHARS".as_bytes().to_vec();
	input.append(&mut [3u8; 3].to_vec());
	println!("{:02x?}", input);
	match ex15::strip_padding(&input) {
		Ok(x) => println!("{:02x?}", x),
		Err(e) => println!("{}", e)
	}

	// ex16
	println!("\nex16:");
	ex16::bitflipping_attack();

}

fn set_three() {

	// ex17
	println!("\nex17:");
	ex17::cbc_padding_oracle();

	// ex18
	println!("\nex18:");
	ex18::decrypt_string();

	// ex19
	println!("\nex19:");
	ex19::break_fixed_nonce_using_substitutions();

	// ex20
	println!("\nex20:");
	ex20::break_fixed_nonce_ctr_statistically();

}

fn current_exercise() {

	// ex21
	println!("\nex21:");
	let mut twister = ex21::MtPrng::new();
	twister.seed_mt(5489);
	let mut c_twister = ex21::CMtPrng::new();
	c_twister.seed_mt(5489);
	
	// http://www.math.sci.hiroshima-u.ac.jp/~m-mat/MT/emt.html
	
	// println!("pre-twist:	{:?}", &twister.mt.to_vec()[..10]);
	// println!("{}", twister.extract_number().unwrap());
	// println!("post-twist:	{:?}", &twister.mt.to_vec()[..10]);
	for _ in 0..50 {
		let x = twister.extract_number().unwrap();
		println!("{}", x);
		assert!(x == c_twister.extract_number().unwrap());
	}
}
