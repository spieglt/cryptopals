/*

Crack an MT19937 seed

Make sure your MT19937 accepts an integer seed value. Test it (verify that you're getting the same sequence of outputs given a seed).

Write a routine that performs the following operation:

    Wait a random number of seconds between, I don't know, 40 and 1000.
    Seeds the RNG with the current Unix timestamp
    Waits a random number of seconds again.
    Returns the first 32 bit output of the RNG.

You get the idea. Go get coffee while it runs. Or just simulate the passage of time, although you're missing some of the fun of this exercise if you do that.

From the 32 bit RNG output, discover the seed.

*/

// Is the point just to seed with every value from the last 80-2000
// seconds and see if the first number generated matches?

use set3::ex21;

use rand::Rng;
use std::time::{Duration, SystemTime};

pub fn crack_mt19937_seed() {
	let mut twister = ex21::MtPrng::new();

	for i in 0..10 {
		let time = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).expect("could not get time");
		let seed_time = time + Duration::from_secs(rand::thread_rng().gen_range(40,1000));
		let sts = seed_time.as_secs() as u32;
		twister.seed_mt(sts);
		let output_time = seed_time + Duration::from_secs(rand::thread_rng().gen_range(40,1000));
		println!("first number: 	{}", twister.extract_number().unwrap());
	}
}