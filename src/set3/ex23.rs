/*

Clone an MT19937 RNG from its output

The internal state of MT19937 consists of 624 32 bit integers.

For each batch of 624 outputs, MT permutes that internal state. By permuting state regularly, MT19937 achieves a period of 2**19937, which is Big.

Each time MT19937 is tapped, an element of its internal state is subjected to a tempering function that diffuses bits through the result.

The tempering function is invertible; you can write an "untemper" function that takes an MT19937 output and transforms it back into the corresponding element of the MT19937 state array.

To invert the temper transform, apply the inverse of each of the operations in the temper transform in reverse order. There are two kinds of operations in the temper transform each applied twice; one is an XOR against a right-shifted value, and the other is an XOR against a left-shifted value AND'd with a magic number. So you'll need code to invert the "right" and the "left" operation.

Once you have "untemper" working, create a new MT19937 generator, tap it for 624 outputs, untemper each of them to recreate the state of the generator, and splice that state into a new instance of the MT19937 generator.

The new "spliced" generator should predict the values of the original.
Stop and think for a second.
How would you modify MT19937 to make this attack hard? What would happen if you subjected each tempered output to a cryptographic hash?

*/

// pub fn extract_number(&mut self) -> Result<u32, String> {
// 	if self.index >= self.n {
// 		if self.index > self.n {
// 			return Err("generator was never seeded".to_string());
// 		}
// 		self.twist();
// 	}
// 	let mut y = self.mt[self.index as usize];
// 	y ^= (y >> self.u) & self.d;
// 	y ^= (y << self.s) & self.b;
// 	y ^= (y << self.t) & self.c;
// 	y ^= y >> self.l;

// 	self.index += 1;
// 	Ok(y)
// }

use set3::ex21;

use std::cmp::min;


fn low_n_bits(inp: u32, n: u32) -> u32 {
	inp ^ ((inp >> n) << n)
}

fn undo_xor_with_right_shift(given: u32, rsv: u32) -> u32 {
	assert!(rsv <= 32);

	let mut known_bits = given >> (32 - rsv);	// must be left-shifted when appended to
	let mut num_known_bits = rsv;
	let mut i = 0;
	while num_known_bits < 32 {
		let num_remainder_bits = 32 - num_known_bits;
		let remainder = low_n_bits(given, num_remainder_bits);
		// grab up to rsv bits to work on
		let num_working_bits = min(rsv, num_remainder_bits);
		let next_chunk = remainder >> (32 - num_known_bits - num_working_bits);
		let relevant_bits = low_n_bits(known_bits, num_known_bits - (rsv * i)) >> (rsv - num_working_bits);
		let extension = relevant_bits ^ next_chunk;
		known_bits = (known_bits << num_working_bits) + extension;
		num_known_bits += num_working_bits;
		i += 1;
	}
	known_bits
}

fn untemper(y: u32) -> u32 {
	0
}


pub fn clone_mt19947_prng() {
	let mut target = ex21::MtPrng::new();
	target.seed_mt(5);

}


#[cfg(test)]
mod tests {
	use set3::ex21;

	#[test]
	fn test_undo_xor_with_right_shift() {
		let mut mt = ex21::MtPrng::new();
		mt.seed_mt(3210952839);
		let mut test_vec = vec![];
		for _ in 0..1000 {
			let mut temp_val = mt.extract_number().unwrap();
			test_vec.push(temp_val);
		}
		println!("{:?}", test_vec);
		for val in test_vec {
			println!("on {}", val);
			for rsv in 1..32 {
				println!("rsv {}", rsv);
				let modified = val ^ (val >> rsv);
				assert_eq!(val, super::undo_xor_with_right_shift(modified, rsv));
			}
		}
	}
}

// fn bit_length(inp: &u32) -> u32 {
// 	(*inp as f32).log2() as u32 + 1
// }