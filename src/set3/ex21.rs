/*

Implement the MT19937 Mersenne Twister RNG

You can get the psuedocode for this from Wikipedia.

If you're writing in Python, Ruby, or (gah) PHP, your language is probably already giving you MT19937 as "rand()"; don't use rand(). Write the RNG yourself.

*/

/* 
https://en.wikipedia.org/wiki/Mersenne_Twister#Pseudocode
The coefficients for MT19937 are:
	(w, n, m, r) = (32, 624, 397, 31)
	a = 0x9908B0DF
	(u, d) = (11, 0xFFFFFFFF)
	(s, b) = (7, 0x9D2C5680)
	(t, c) = (15, 0xEFC60000)
	l = 18

	d = 0xFFFFFFFF

// Create a length n array to store the state of the generator
int[0..n-1] MT
int index := n+1
const int lower_mask = (1 << r) - 1 // That is, the binary number of r 1's
const int upper_mask = lowest w bits of (not lower_mask)

 // Initialize the generator from a seed
 function seed_mt(int seed) {
	 index := n
	 MT[0] := seed
	 for i from 1 to (n - 1) { // loop over each element
		 MT[i] := lowest w bits of (f * (MT[i-1] xor (MT[i-1] >> (w-2))) + i)
	 }
 }
 
 // Extract a tempered value based on MT[index]
 // calling twist() every n numbers
 function extract_number() {
	 if index >= n {
		 if index > n {
		   error "Generator was never seeded"
		   // Alternatively, seed with constant value; 5489 is used in reference C code[46]
		 }
		 twist()
	 }
 
	 int y := MT[index]
	 y := y xor ((y >> u) and d)
	 y := y xor ((y << s) and b)
	 y := y xor ((y << t) and c)
	 y := y xor (y >> l)
 
	 index := index + 1
	 return lowest w bits of (y)
 }
 
 // Generate the next n values from the series x_i 
 function twist() {
	 for i from 0 to (n-1) {
		 int x := (MT[i] and upper_mask)
				   + (MT[(i+1) mod n] and lower_mask)
		 int xA := x >> 1
		 if (x mod 2) != 0 { // lowest bit of x is 1
			 xA := xA xor a
		 }
		 MT[i] := MT[(i + m) mod n] xor xA
	 }
	 index := 0
 }

*/

pub struct MtPrng {
	pub w: i64,
	pub n: i64,
	pub m: i64,
	pub r: i64,
	pub a: i64,
	pub u: i64,
	pub d: i64,
	pub s: i64,
	pub b: i64,
	pub t: i64,
	pub c: i64,
	pub l: i64,
	pub f: i64,
	pub index: i64,
	pub lower_mask: i64,
	pub upper_mask: i64,
	pub mt: [i64; 624] // len n
}

impl MtPrng {
	pub fn new() -> MtPrng {
		let w = 32;
		let n = 624;
		let r = 31;
		let mt = [0; 624];
		let index = n + 1;
		let lower_mask = (1 << r) - 1_i64;
		println!("lower mask: {:032b}", lower_mask);
		let upper_mask = !lower_mask & ((1 << w) - 1);
		println!("upper mask: {:032b}", upper_mask);

		MtPrng {
			w: 32,
			n: 624,
			m: 397,
			r: 31,
			a: 0x9908B0DF,
			u: 11,
			d: 0xFFFFFFFF,
			s: 7,
			b: 0x9D2C5680,
			t: 15,
			c: 0xEFC60000,
			l: 18,
			f: 1812433253,
			index: index,
			lower_mask: lower_mask,
			upper_mask: upper_mask,
			mt: mt,
		}
	}

	pub fn seed_mt(&mut self, seed: i64) {
	// 	 index := n
	// MT[0] := seed
	// for i from 1 to (n - 1) { // loop over each element
	//		MT[i] := lowest w bits of (f * (MT[i-1] xor (MT[i-1] >> (w-2))) + i)
	// }
		self.index = self.n;
		self.mt[0] = seed;
		for i in 1..self.mt.len() {
			self.mt[i] = (self.f * (self.mt[i-1] ^ (self.mt[i-1] >> (self.w - 2)))) & ((1 << self.w) - 1)
		}
	}
}
