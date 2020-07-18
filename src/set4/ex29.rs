/*

Break a SHA-1 keyed MAC using length extension

Secret-prefix SHA-1 MACs are trivially breakable.

The attack on secret-prefix SHA1 relies on the fact that you can take the ouput of SHA-1 and use it as a new starting point for SHA-1, thus taking an arbitrary SHA-1 hash and "feeding it more data".

Since the key precedes the data in secret-prefix, any additional data you feed the SHA-1 hash in this fashion will appear to have been hashed with the secret key.

To carry out the attack, you'll need to account for the fact that SHA-1 is "padded" with the bit-length of the message; your forged message will need to include that padding. We call this "glue padding". The final message you actually forge will be:

SHA1(key || original-message || glue-padding || new-message)

(where the final padding on the whole constructed message is implied)

Note that to generate the glue padding, you'll need to know the original bit length of the message; the message itself is known to the attacker, but the secret key isn't, so you'll need to guess at it.

This sounds more complicated than it is in practice.

To implement the attack, first write the function that computes the MD padding of an arbitrary message and verify that you're generating the same padding that your SHA-1 implementation is using. This should take you 5-10 minutes.

Now, take the SHA-1 secret-prefix MAC of the message you want to forge --- this is just a SHA-1 hash --- and break it into 32 bit SHA-1 registers (SHA-1 calls them "a", "b", "c", &c).

Modify your SHA-1 implementation so that callers can pass in new values for "a", "b", "c" &c (they normally start at magic numbers). With the registers "fixated", hash the additional data you want to forge.

Using this attack, generate a secret-prefix MAC under a secret key (choose a random word from /usr/share/dict/words or something) of the string:

"comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"

Forge a variant of this message that ends with ";admin=true".
This is a very useful attack.

For instance: Thai Duong and Juliano Rizzo, who got to this attack before we did, used it to break the Flickr API.

*/

use crate::utils;
use crate::ex28;
use rand::{Rng, thread_rng};

fn pad_message(message: &Vec<u8>, excess: usize) -> Vec<u8> {
    // message needs to be multiple of 512 bits/64 bytes
    let padding_len = 64 - ((message.len() + excess) % 64);
    let mut padded = message.clone();
    // padding starts with 0x80/0b10000000
    padded.push(0x80);
    // then zeroes. padding_len - 9: one for the 0x80 byte and eight for the message size.
    let mut zeroes = vec![0; padding_len - 9];
    padded.append(&mut zeroes);
    // then last 8 bytes should be length of the message (64-bit int, big-endian says Wikipedia)
    let l = (message.len() + excess) as u64;
    for i in 0..8 {
        padded.push(((l >> (8*(7 - i))) & 0xFF) as u8);
    }
    // utils::print_invalid_string(&padded);
    // println!("{:02x?}\n{}", padded, padded.len());
    // assert!((padded.len() * 8) % 512 == 0, "padding not congruent to 512 bits");
    // padded vec construction: [ message | 0x80 | (padding_len - 9) bytes of zeroes | 64-bit message size ]
    padded
}

pub fn break_sha1_keyed_mac() {
    let orig_message = "comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"
        .as_bytes().to_vec();
    // let mut padded = pad_message(&orig_message);

    // the goal is just to make our message pass the authenticate function. we don't need to know the key,
    // we just need to know its length which is much easier to guess at
    // so, forgery = fakekeyofunknownlength + original message which we know + padding bytes + new message
    // then the SHA1 lib will add the real final padding for us, and we adjust the fake key's length until one passes the auth function.
    let key = (0..16).map(|_| thread_rng().gen::<u8>()).collect();
    let mut s1km = ex28::Sha1KeyedMac::new(&key);
    let orig_hash = s1km.gen(&orig_message);
    println!("{:02x?}\n{}", orig_hash, orig_hash.len());

    let mut registers = [0u32; 5];
    for i in 0..5 {
        for j in 0..4 {
            registers[i] <<= 8;
            registers[i] |= orig_hash[(4*i) + j] as u32
        }
    }
    println!("{:02x?}", registers);
    
    let mut hasher = ex28::Sha1KeyedMac::custom(registers, &key);
    let mut new_data = ";admin=true".as_bytes().to_vec();
    let new_hash = hasher.gen(&new_data);

    // let mut fake_pw_len = 0;
    for i in 0..20 {
        let mut padded = pad_message(&orig_message, i);
        let mut forgery = vec![0x41u8; i];
        forgery.append(&mut padded);
        forgery.append(&mut new_data.clone());
        match hasher.authenticate(&new_hash, &forgery) {
            true => println!("forged!"),
            // false => utils::print_invalid_string(&forgery),
            false => (),
        }
    }

}
