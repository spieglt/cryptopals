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

// given = x ^ (x >> 18)
// how to get x? we're looking for a number that, when xor'd with itself bitshifted, gives us known number
// if i have 				10100101011010101010010101101101, and right-shift by 18,
// then i have				00000000000000000010100101011010

// xor of these = given		10100101011010101000110000110111

// so from given, i know that top 18 bits are from the original,
// and the bottom 14 bits should be the xor of bottom 14 bits of given and top 14 bits of given

//////////////////////////////////////////////////////////////////////////////////////////////

// what about 11?		
// if i have 				10100101011010101010010101101101, and right-shift by 11,
// then i have				00000000000101001010110101010100

//							gggggggggggbbbbbbbbbbbbbbbbbbbbb
// xor of these = given		10100101011111100000100000111001

// so i know top 11 are good, next 11 need to be xor'd with first 11, then i have 22
//							10100101011010101010010000111001

// then i can start over, knowing that the bottom 10 will be (bottom 10 of given ^ bottom 10 of top 32 - 11)

//////////////////////////////////////////////////////////////////////////////////////////////

use set3::ex21;

use std::cmp::min;

fn bit_length(inp: &u32) -> u32 {
	match inp {
		0 => f32::from_bits(*inp).log2() as u32,
		_ => f32::from_bits(*inp).log2() as u32 + 1,
	}
}

fn undo_xor_with_right_shift(given: u32, rsv: usize) -> u32 {
	assert!(rsv <= 32);

	let mut known_bits = given >> (32 - rsv);	// must be left-shifted when appended to
	
	while bit_length(&known_bits) < 32 {
		// to mask off high bits, get known bits on the left, then xor it
		let remainder = given ^ (known_bits << (32 - bit_length(&known_bits)));	// remainder == given without known bits
		// want to grab up to bit_length(known_bits) top bits of remainder (get max)
		let num_working_bits = min(bit_length(&known_bits), bit_length(&remainder));
		let working_known_bits = known_bits >> (bit_length(&known_bits) - num_working_bits);
		let chopped_remainder = remainder >> (bit_length(&remainder) - num_working_bits);
		// then xor them with max result number of known bits, then left shift known_bits by bit_length of extension, then add extension
		let extension = working_known_bits ^ chopped_remainder;
		known_bits = known_bits << bit_length(&extension) + extension;
	}
	known_bits
}

fn untemper(y: u32) -> u32 {
	0
}

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

pub fn clone_mt19947_prng() {
	let mut target = ex21::MtPrng::new();
	target.seed_mt(5);


}


#[cfg(test)]
mod tests {
	#[test]
	fn test_undo_xor_with_right_shift() {
		for i in 0..1000 {
			for rsv in 1..32 {
				let modified = i ^ (i >> rsv);
				assert_eq!(i, super::undo_xor_with_right_shift(modified, rsv));
			}
		}
	}
}
