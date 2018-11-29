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
	pub w: u32,
	pub n: u32,
	pub m: u32,
	pub r: u32,
	pub a: u32,
	pub u: u32,
	pub d: u32,
	pub s: u32,
	pub b: u32,
	pub t: u32,
	pub c: u32,
	pub l: u32,
	pub f: u32,
	pub index: u32,
	pub lower_mask: u32,
	pub upper_mask: u32,
	pub mt: [u32; 624] // len n
}

impl MtPrng {
	pub fn new() -> MtPrng {
		let w = 32;
		let n = 624;
		let r = 31;
		let mt = [0; 624];
		let index = n + 1;
		let lower_mask = (1 << r) - 1_u32;
		println!("lower mask: {:02x}", lower_mask);
		let upper_mask = !lower_mask & 0xFFFFFFFF;
		println!("upper mask: {:02x}", upper_mask);

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

	pub fn seed_mt(&mut self, seed: u32) {
		self.index = self.n;
		self.mt[0] = seed;
		for i in 1..self.mt.len() {
			// std::u32::MAX problem but also multiplication past u32 problem
			self.mt[i] = self.d & 
							(self.f as u64 * 
								(self.mt[i-1] ^ 
									(self.mt[i-1] >> (self.w - 2))
								) as u64
								+ i as u64
							) as u32;
			self.mt[i] &= self.d;
		}
	}

	pub fn extract_number(&mut self) -> Result<u32, String> {
		if self.index >= self.n {
			if self.index > self.n {
				return Err("generator was never seeded".to_string());
			}
			self.twist()
		}
		let mut y = self.mt[self.index as usize];
		y ^= (y >> self.u) & self.d;
		y ^= (y << self.s) & self.b;
		y ^= (y << self.t) & self.c;
		y ^= y >> self.l;

		self.index += 1;
		Ok(y & self.d)
	}

	pub fn twist(&mut self) {
		for _i in 0..self.n {
			let i = _i as usize;
			let x = (self.mt[i] & self.upper_mask) + (self.mt[(i + 1) % self.n as usize] & self.lower_mask);
			let mut x_a = x >> 1;
			if x % 2 != 0 {
				x_a ^= self.a;
			}
			self.mt[i] = self.mt[(i + self.m as usize) % self.n as usize] ^ x_a;
		}
		self.index = 0;
	}
}

pub struct CMtPrng {
	pub w: u32,
	pub n: u32,
	pub m: u32,
	pub r: u32,
	pub a: u32,
	pub u: u32,
	pub d: u32,
	pub s: u32,
	pub b: u32,
	pub t: u32,
	pub c: u32,
	pub l: u32,
	pub f: u32,
	pub index: u32,
	pub lower_mask: u32,
	pub upper_mask: u32,
	pub mt: [u32; 624] // len n
}

impl CMtPrng {
	pub fn new() -> MtPrng {
		let w = 32;
		let n = 624;
		let r = 31;
		let mt = [0; 624];
		let index = n + 1;
		let lower_mask = (1 << r) - 1_u32;
		println!("lower mask: {:02x}", lower_mask);
		let upper_mask = !lower_mask & 0xFFFFFFFF;
		println!("upper mask: {:02x}", upper_mask);

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

	pub fn seed_mt(&mut self, seed: u32) {
		self.index = self.n;
		self.mt[0] = seed;
		for i in 1..self.mt.len() {
			// std::u32::MAX problem but also multiplication past u32 problem
			self.mt[i] = self.d & 
							(self.f as u64 * 
								(self.mt[i-1] ^ 
									(self.mt[i-1] >> (self.w - 2))
								) as u64
								+ i as u64
							) as u32;
			self.mt[i] &= self.d;
		}
	}

	pub fn extract_number(&mut self) -> Result<u32, String> {
		if self.index >= self.n {
			if self.index > self.n {
				return Err("generator was never seeded".to_string());
			}
			self.twist()
		}
		let mut y = self.mt[self.index as usize];
		y ^= (y >> self.u) & self.d;
		y ^= (y << self.s) & self.b;
		y ^= (y << self.t) & self.c;
		y ^= y >> self.l;

		self.index += 1;
		Ok(y & self.d)
	}

	pub fn twist(&mut self) {
		let mag01 = [0, self.a];
		for _kk in 0..self.n-self.m {
			let kk = _kk as usize;
			let y = (self.mt[kk] & self.upper_mask) | (self.mt[kk+1] & self.lower_mask);
			self.mt[kk] = self.mt[kk + self.m as usize] ^
									(y >> 1) ^ 
									mag01[y as usize & 1];
		}
		for _kk in self.n-self.m..self.n-1 {
			let kk = _kk as usize;
			let y = (self.mt[kk] & self.upper_mask) | (self.mt[kk + 1] & self.lower_mask);
			self.mt[kk] = self.mt[kk + 397 - 624] ^ (y >> 1) ^ mag01[y as usize & 1];
		}
		let y = (self.mt[self.n as usize - 1] & self.upper_mask) | 
				(self.mt[0] & self.lower_mask);
		self.mt[self.n as usize - 1] = self.mt[self.m as usize - 1] ^ (y >> 1) ^ mag01[y as usize & 1];
		self.index = 0
	}
}
