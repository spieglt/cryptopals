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

pub fn mersenne_twister_prng() {
	let (w, n, m, r) = (32_i64, 624_i64, 397_i64, 31_i64);
	let a = 0x9908B0DF_i64;
    let (u, d) = (11_i64, 0xFFFFFFFF_i64);
    let (s, b) = (7_i64, 0x9D2C5680_i64);
    let (t, c) = (15_i64, 0xEFC60000_i64);
    let l = 18_i64;

	let mt = vec![0; n as usize];
	let mut index = n + 1;
	let mut lower_mask = (1 << r);
	lower_mask -= 1_u64;
	println!("lower mask: {:032b}", lower_mask);
	let upper_mask = !lower_mask & ((1 << w) - 1);
	println!("upper mask: {:032b}", upper_mask);
}