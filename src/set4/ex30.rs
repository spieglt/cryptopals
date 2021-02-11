/*
Break an MD4 keyed MAC using length extension

Second verse, same as the first, but use MD4 instead of SHA-1. Having done this attack once against SHA-1, the MD4 variant should take much less time; mostly just the time you'll spend Googling for an implementation of MD4.
You're thinking, why did we bother with this?

Blame Stripe. In their second CTF game, the second-to-last challenge involved breaking an H(k, m) MAC with SHA1. Which meant that SHA1 code was floating all over the Internet. MD4 code, not so much.
*/

use md4::{Md4, Digest};
use rand::{Rng, thread_rng};

pub struct Md4KeyedMac {
    pub md4: md4::Md4,
    key: Vec<u8>,
}

impl Md4KeyedMac {
    pub fn new(key: &Vec<u8>) -> Md4KeyedMac {
        let hasher = Md4::new();
        Md4KeyedMac {
            md4: hasher,
            key: key.clone(),
        }
    }
}

pub fn md4_keyed_mac() {
	let key = (0..16).map(|_| thread_rng().gen::<u8>()).collect();
	let mut _s1km = Md4KeyedMac::new(&key);

}